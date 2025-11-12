require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const DatabaseAdapter = require('./database-adapter');
const path = require('path');
const axios = require('axios');
const fs = require('fs').promises;
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const https = require('https');
const querystring = require('querystring');
const crypto = require('crypto');

// ==========================================
// CONFIGURATION & ENVIRONMENT VARIABLES
// ==========================================

const app = express();
const PORT = process.env.PORT || 3000;

// API Keys - Set these in your environment
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('❌ CRITICAL: JWT_SECRET environment variable is required for security');
  process.exit(1);
}
const OUTSCRAPER_API_KEY = process.env.OUTSCRAPER_API_KEY;
const SCRAPINGBEE_API_KEY = process.env.SCRAPINGBEE_API_KEY;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const SERPAPI_KEY = process.env.SERPAPI_KEY;

// Validate critical API keys on startup
const missingKeys = [];
if (!OUTSCRAPER_API_KEY) missingKeys.push('OUTSCRAPER_API_KEY');
if (!SCRAPINGBEE_API_KEY) missingKeys.push('SCRAPINGBEE_API_KEY');
if (!OPENAI_API_KEY) missingKeys.push('OPENAI_API_KEY');
if (!SERPAPI_KEY) missingKeys.push('SERPAPI_KEY');

if (missingKeys.length > 0) {
  console.error('❌ CRITICAL: Missing required API keys:');
  missingKeys.forEach(key => console.error(`   - ${key}`));
  console.error('🚨 Application cannot function without these API keys. Please add them to your environment.');
  process.exit(1);
}

// Stripe Configuration  
const STRIPE_PRICES = {
  oneTime: process.env.STRIPE_PRICE_ONE_TIME || 'price_1Ro50jDEq7s1BPEYpT3Hexlh',
  pro: process.env.STRIPE_PRICE_STARTER || 'price_1Ro501DEq7s1BPEYrXB78dyu', // 50 credits - renamed from starter to pro
  premium: process.env.STRIPE_PRICE_PRO || 'price_1ReR1MDEq7s1BPEYHzSW0uTn'  // 100 credits - renamed from pro to premium
};

const CREDIT_AMOUNTS = {
  oneTime: 1,
  pro: 50,      // Renamed from "starter" to match Stripe
  premium: 100  // Renamed from "pro" to match Stripe
};

// White Label Configuration
const BRAND_CONFIG = {
  name: process.env.BRAND_NAME || 'Locality',
  logo: process.env.BRAND_LOGO || 'locality-logo.png',
  primaryColor: process.env.BRAND_PRIMARY_COLOR || '#0e192b',
  supportEmail: process.env.BRAND_SUPPORT_EMAIL || 'support@locality.com',
  preparedBySuffix: process.env.BRAND_PREPARED_BY_SUFFIX || 'Marketing'
};
// ==========================================
// DATABASE SETUP
// ==========================================

// Initialize database
const db = new DatabaseAdapter();

// Initialize database connection
(async () => {
  try {
    await db.initialize();
    await db.setupTables();
    console.log('✅ Database ready for connections');
    
  } catch (err) {
    console.error('❌ Database initialization failed:', err);
    process.exit(1);
  }
})();

// ==========================================
// MIDDLEWARE
// ==========================================

// CORS configuration - only allow your domains
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : [
      'https://app.trylocality.com',
      'https://seo-saas-tool.onrender.com',
      'http://localhost:3000'
    ];

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc)
    if (!origin) return callback(null, true);

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log(`❌ CORS blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting configuration
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 login attempts per 15 minutes
  skipSuccessfulRequests: true,
  message: 'Too many login attempts, please try again in 15 minutes.',
});

const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 password reset requests per hour
  message: 'Too many password reset requests, please try again later.',
});

const reportLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // Max 10 reports per minute per IP
  message: 'Generating reports too quickly, please slow down.',
});

// Apply general rate limiting to all API routes
app.use('/api/', apiLimiter);

app.use('/api/stripe-webhook', express.raw({ type: 'application/json' }));
app.use(express.json());
// Serve static files with cache control
app.use(express.static('public', {
  setHeaders: (res, path) => {
    // Cache HTML files for a short time to prevent auth state issues
    if (path.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
    // Cache other assets normally
    else {
      res.setHeader('Cache-Control', 'public, max-age=86400'); // 24 hours
    }
  }
}));

// Serve email verification page
app.get('/verify-email', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'verify-email.html'));
});

// ==========================================
// UTILITY FUNCTIONS
// ==========================================

// Password strength validation
function validatePassword(password) {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  if (password.length < minLength) {
    return { valid: false, error: 'Password must be at least 8 characters long' };
  }
  if (!hasUpperCase || !hasLowerCase) {
    return { valid: false, error: 'Password must contain both uppercase and lowercase letters' };
  }
  if (!hasNumbers) {
    return { valid: false, error: 'Password must contain at least one number' };
  }
  if (!hasSpecialChar) {
    return { valid: false, error: 'Password must contain at least one special character (!@#$%^&*...)' };
  }

  return { valid: true };
}

// HTML sanitization function for XSS protection
function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return unsafe
    .toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ==========================================
// AUTH MIDDLEWARE
// ==========================================

// Auth middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await db.get('SELECT * FROM users WHERE id = $1', [decoded.userId]);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'JsonWebTokenError') {
      return res.status(403).json({ error: 'Invalid token' });
    }
    console.error('Database error in auth:', err);
    return res.status(500).json({ error: 'Database error' });
  }
};
// ==========================================
// UTILITY FUNCTIONS
// ==========================================

// Ensure screenshots directory exists
const screenshotsDir = path.join(__dirname, 'public', 'screenshots');
async function ensureScreenshotsDir() {
  try {
    await fs.mkdir(screenshotsDir, { recursive: true });
  } catch (error) {
    console.log('Screenshots directory already exists or created');
  }
}

// Clean expired cache entries
async function cleanupExpiredCache() {
  try {
    // Use NOW() for PostgreSQL compatibility, DATETIME('now') for SQLite
    const query = db.dbType === 'postgresql' 
      ? 'DELETE FROM screenshot_cache WHERE expires_at < NOW()'
      : 'DELETE FROM screenshot_cache WHERE expires_at < datetime("now")';
    
    const result = await db.run(query);
    if (result.changes > 0) {
      console.log(`🧹 Cleaned up ${result.changes} expired cached screenshots`);
    }
  } catch (err) {
    console.error('Cache cleanup error:', err);
  }
}

// Run cleanup every 24 hours
setInterval(cleanupExpiredCache, 24 * 60 * 60 * 1000);

// ==========================================
// DATA COLLECTION FUNCTIONS
// ==========================================

// Helper function to detect country and region from location string
function detectCountryRegion(location) {
  const locationLower = location.toLowerCase();
  
  // Common country indicators
  const countryMappings = {
    // Middle East
    'united arab emirates': { region: 'AE', language: 'en' },
    'uae': { region: 'AE', language: 'en' },
    'dubai': { region: 'AE', language: 'en' },
    'abu dhabi': { region: 'AE', language: 'en' },
    'sharjah': { region: 'AE', language: 'en' },
    'saudi arabia': { region: 'SA', language: 'en' },
    'qatar': { region: 'QA', language: 'en' },
    'kuwait': { region: 'KW', language: 'en' },
    'bahrain': { region: 'BH', language: 'en' },
    'oman': { region: 'OM', language: 'en' },
    
    // Europe
    'united kingdom': { region: 'GB', language: 'en' },
    'uk': { region: 'GB', language: 'en' },
    'england': { region: 'GB', language: 'en' },
    'london': { region: 'GB', language: 'en' },
    'germany': { region: 'DE', language: 'en' },
    'france': { region: 'FR', language: 'en' },
    'spain': { region: 'ES', language: 'en' },
    'italy': { region: 'IT', language: 'en' },
    'netherlands': { region: 'NL', language: 'en' },
    'belgium': { region: 'BE', language: 'en' },
    'switzerland': { region: 'CH', language: 'en' },
    
    // Asia Pacific
    'australia': { region: 'AU', language: 'en' },
    'sydney': { region: 'AU', language: 'en' },
    'melbourne': { region: 'AU', language: 'en' },
    'new zealand': { region: 'NZ', language: 'en' },
    'singapore': { region: 'SG', language: 'en' },
    'hong kong': { region: 'HK', language: 'en' },
    'japan': { region: 'JP', language: 'en' },
    'india': { region: 'IN', language: 'en' },
    
    // Americas
    'canada': { region: 'CA', language: 'en' },
    'toronto': { region: 'CA', language: 'en' },
    'vancouver': { region: 'CA', language: 'en' },
    'mexico': { region: 'MX', language: 'en' },
    'brazil': { region: 'BR', language: 'en' },
    'argentina': { region: 'AR', language: 'en' }
  };
  
  // Check for country/city matches
  for (const [key, value] of Object.entries(countryMappings)) {
    if (locationLower.includes(key)) {
      console.log(`🌍 Detected location: ${key} -> Region: ${value.region}`);
      return value;
    }
  }
  
  // Default to US if no specific country detected
  return { region: 'US', language: 'en' };
}

// ==========================================
// EMAIL FUNCTIONS
// ==========================================

// Generate secure random token
function generateSecureToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Send new user notification
async function sendNewUserNotification(userData) {
  const { userId, email, firstName, lastName, signupDate, plan, initialCredits } = userData;
  
  // Notification content
  const subject = `🎉 New User Signup - ${email}`;
  const notificationBody = `
New user registered on SEO Audit Tool:

👤 User Information:
   • Name: ${firstName} ${lastName}
   • Email: ${email}
   • User ID: ${userId}
   • Plan: ${plan}
   • Initial Credits: ${initialCredits}
   • Signup Date: ${new Date(signupDate).toLocaleString()}

📊 Quick Actions:
   • View all users: https://yourdomain.com/api/admin/users
   • Export to CSV: https://yourdomain.com/api/admin/users/export
`;

  // Log to console (always works)
  console.log('===============================================');
  console.log('🎉 NEW USER NOTIFICATION');
  console.log('===============================================');
  console.log(notificationBody);
  console.log('===============================================');
  
  // Send to webhook if configured
  const webhookUrl = process.env.NEW_USER_WEBHOOK_URL || process.env.FEEDBACK_WEBHOOK_URL;
  if (webhookUrl) {
    try {
      const webhookData = {
        subject,
        body: notificationBody,
        type: 'new_user',
        data: userData,
        emailType: 'new_user_notification',
        timestamp: new Date().toISOString()
      };
      
      console.log(`🔗 Sending new user notification to webhook: ${webhookUrl}`);
      
      await axios.post(webhookUrl, webhookData, {
        timeout: 5000,
        headers: { 'Content-Type': 'application/json' }
      });
      
      console.log('✅ New user webhook notification sent');
    } catch (error) {
      console.error('❌ Failed to send new user webhook:', error.message);
    }
  } else {
    console.warn('⚠️ No NEW_USER_WEBHOOK_URL configured');
  }
}

// Generic email sending function
async function sendEmail(to, subject, htmlContent, textContent) {
  const webhookUrl = process.env.EMAIL_WEBHOOK_URL || process.env.FEEDBACK_WEBHOOK_URL;
  return sendEmailWithWebhook(to, subject, htmlContent, textContent, webhookUrl, 'generic_email');
}

// Email sending with specific webhook
async function sendEmailWithWebhook(to, subject, htmlContent, textContent, webhookUrl, emailType) {
  try {
    // Method 1: Log to console (always works for debugging)
    console.log(`📧 EMAIL NOTIFICATION (${emailType}):`);
    console.log('To:', to);
    console.log('Subject:', subject);
    console.log('Body:', textContent || htmlContent);
    
    // Method 2: Try to use a webhook service (like Zapier, n8n, or similar)
    if (webhookUrl) {
      const webhookData = {
        to: to,
        subject: subject,
        html: htmlContent,
        text: textContent,
        type: emailType,  // Add type field for Zapier path filtering
        emailType: emailType,
        timestamp: new Date().toISOString()
      };
      
      console.log(`🔗 Sending to webhook: ${webhookUrl}`);
      
      await axios.post(webhookUrl, webhookData, {
        timeout: 5000,
        headers: { 'Content-Type': 'application/json' }
      });
      
      console.log(`✅ ${emailType} webhook sent successfully`);
    } else {
      console.warn(`⚠️ No webhook URL configured for ${emailType}`);
    }
    
    return true;
  } catch (error) {
    console.error(`❌ ${emailType} webhook failed:`, error.message);
    throw error;
  }
}

// Send email verification
async function sendVerificationEmail(email, firstName, verificationToken) {
  const verificationUrl = `${process.env.APP_URL || `http://localhost:${PORT}`}/verify-email?token=${verificationToken}`;
  
  const subject = 'Verify your email - Locality';
  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2>Welcome to Locality, ${firstName}!</h2>
      <p>Please verify your email address by clicking the button below:</p>
      <div style="margin: 30px 0;">
        <a href="${verificationUrl}" style="background-color: #0e192b; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
          Verify Email Address
        </a>
      </div>
      <p>Or copy and paste this link into your browser:</p>
      <p style="word-break: break-all;">${verificationUrl}</p>
      <p style="color: #666; font-size: 14px;">This link will expire in 24 hours.</p>
      <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
      <p style="color: #999; font-size: 12px;">If you didn't create an account with Locality, please ignore this email.</p>
    </div>
  `;
  
  const textContent = `
Welcome to Locality, ${firstName}!

Please verify your email address by visiting this link:
${verificationUrl}

This link will expire in 24 hours.

If you didn't create an account with Locality, please ignore this email.
  `.trim();
  
  // Use specific webhook for email verification
  const webhookUrl = process.env.EMAIL_VERIFICATION_WEBHOOK_URL || process.env.EMAIL_WEBHOOK_URL || process.env.FEEDBACK_WEBHOOK_URL;
  return sendEmailWithWebhook(email, subject, htmlContent, textContent, webhookUrl, 'email_verification');
}

// Send password reset email
async function sendPasswordResetEmail(email, firstName, resetToken) {
  const resetUrl = `${process.env.APP_URL || `http://localhost:${PORT}`}/reset-password.html?token=${resetToken}`;
  
  const subject = 'Reset your password - Locality';
  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2>Password Reset Request</h2>
      <p>Hi ${firstName},</p>
      <p>We received a request to reset your password. Click the button below to create a new password:</p>
      <div style="margin: 30px 0;">
        <a href="${resetUrl}" style="background-color: #0e192b; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
          Reset Password
        </a>
      </div>
      <p>Or copy and paste this link into your browser:</p>
      <p style="word-break: break-all;">${resetUrl}</p>
      <p style="color: #666; font-size: 14px;">This link will expire in 1 hour.</p>
      <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
      <p style="color: #999; font-size: 12px;">If you didn't request a password reset, please ignore this email. Your password will remain unchanged.</p>
    </div>
  `;
  
  const textContent = `
Password Reset Request

Hi ${firstName},

We received a request to reset your password. Visit this link to create a new password:
${resetUrl}

This link will expire in 1 hour.

If you didn't request a password reset, please ignore this email. Your password will remain unchanged.
  `.trim();
  
  // Use specific webhook for password reset
  const webhookUrl = process.env.PASSWORD_RESET_WEBHOOK_URL || process.env.EMAIL_WEBHOOK_URL || process.env.FEEDBACK_WEBHOOK_URL;
  return sendEmailWithWebhook(email, subject, htmlContent, textContent, webhookUrl, 'password_reset');
}

/**
 * Send bulk audit completion email notification
 * Notifies users when their bulk audit has finished processing
 * @param {Object} auditData - Contains userEmail, userName, userId, industry, location, businessesScanned, averageScore, creditsUsed, completedAt
 */
async function sendBulkAuditCompleteEmail(auditData) {
  const { userEmail, userName, userId, industry, location, businessesScanned, averageScore, creditsUsed, completedAt } = auditData;

  const subject = `✅ Your Bulk Audit is Complete - ${businessesScanned} Businesses Analyzed`;

  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #0e192b;">🎉 Bulk Audit Complete!</h2>
      <p>Hi ${userName},</p>
      <p>Your bulk SEO audit has finished processing. Here's a summary of your results:</p>

      <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3 style="color: #0e192b; margin-top: 0;">📊 Audit Summary</h3>
        <ul style="line-height: 1.8; color: #333;">
          <li><strong>Industry:</strong> ${industry}</li>
          <li><strong>Location:</strong> ${location}</li>
          <li><strong>Businesses Scanned:</strong> ${businessesScanned}</li>
          <li><strong>Average Score:</strong> ${averageScore}%</li>
          <li><strong>Credits Used:</strong> ${creditsUsed}</li>
          <li><strong>Completed:</strong> ${completedAt}</li>
        </ul>
      </div>

      <p>Your complete competitive analysis report is ready to view in your dashboard.</p>

      <div style="margin: 30px 0; text-align: center;">
        <a href="${process.env.APP_URL || 'http://localhost:3000'}" style="background-color: #0e192b; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
          View Your Report
        </a>
      </div>

      <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
      <p style="color: #999; font-size: 12px;">This is an automated notification from Locality SEO Audit Tool.</p>
    </div>
  `;

  const textContent = `
Bulk Audit Complete!

Hi ${userName},

Your bulk SEO audit has finished processing. Here's a summary of your results:

📊 Audit Summary:
• Industry: ${industry}
• Location: ${location}
• Businesses Scanned: ${businessesScanned}
• Average Score: ${averageScore}%
• Credits Used: ${creditsUsed}
• Completed: ${completedAt}

Your complete competitive analysis report is ready to view in your dashboard.

Visit: ${process.env.APP_URL || 'http://localhost:3000'}

---
This is an automated notification from Locality SEO Audit Tool.
  `.trim();

  // Use specific webhook for bulk audit completion
  const webhookUrl = process.env.BULK_AUDIT_WEBHOOK_URL || process.env.EMAIL_WEBHOOK_URL || process.env.FEEDBACK_WEBHOOK_URL;
  return sendEmailWithWebhook(userEmail, subject, htmlContent, textContent, webhookUrl, 'bulk_audit_complete');
}

// Send feedback email notification
async function sendFeedbackEmail(feedbackData) {
  const { rating, type, message, email, reportData, userId, userName } = feedbackData;

  // Email content
  const subject = `🔔 New Feedback Submission - ${rating}/5 stars`;
  const emailBody = `
New feedback received from SEO Audit Tool:

👤 User Information:
   • Name: ${userName}
   • User ID: ${userId}
   • Contact Email: ${email || 'Not provided'}

⭐ Rating: ${rating}/5 stars
📂 Type: ${type}

💬 Message:
${message}

📊 Related Report:
${reportData ? `   • Business: ${reportData.businessName}
   • Location: ${reportData.location}
   • Industry: ${reportData.industry}` : 'No report data associated'}

⏰ Submitted: ${new Date().toLocaleString()}

---
This feedback was submitted through the Locality SEO Audit Tool.
  `.trim();

  try {
    // Method 1: Log to console (always works for debugging)
    console.log('📧 FEEDBACK EMAIL NOTIFICATION:');
    console.log('To: trylocality@gmail.com');
    console.log('Subject:', subject);
    console.log('Body:', emailBody);

    // Send to feedback webhook
    const webhookUrl = process.env.FEEDBACK_WEBHOOK_URL;
    if (webhookUrl) {
      const webhookData = {
        to: 'trylocality@gmail.com',
        subject: subject,
        body: emailBody,
        feedbackData: feedbackData,
        type: 'feedback_submission',  // Add type field for Zapier path filtering
        emailType: 'feedback_submission',
        timestamp: new Date().toISOString()
      };

      console.log(`🔗 Sending feedback to webhook: ${webhookUrl}`);

      await axios.post(webhookUrl, webhookData, {
        timeout: 5000,
        headers: { 'Content-Type': 'application/json' }
      });

      console.log('✅ Feedback webhook sent successfully');
    } else {
      console.warn('⚠️ No FEEDBACK_WEBHOOK_URL configured');
    }

    return true;
  } catch (error) {
    console.error('❌ Email sending failed:', error.message);
    throw error;
  }
}

// Send citation order notification email
async function sendCitationOrderEmail(orderData) {
  const {
    packageSize,
    businessName,
    businessAddress,
    businessPhone,
    customerName,
    customerEmail,
    amountPaid,
    priorityCitations,
    existingCitations,
    missingCount,
    foundCount,
    totalAnalyzed
  } = orderData;

  // Format priority citations list
  let priorityList = 'None specified';
  if (priorityCitations && priorityCitations.length > 0) {
    priorityList = priorityCitations.map((citation, index) => {
      const issue = citation.issue ? ` (${citation.issue})` : '';
      return `   ${index + 1}. ${citation.directory}${issue}`;
    }).join('\n');
  }

  // Format existing citations list
  let existingList = 'None found';
  if (existingCitations && existingCitations.length > 0) {
    existingList = existingCitations.map((citation, index) => {
      const url = citation.url ? ` - ${citation.url}` : '';
      return `   ${index + 1}. ${citation.directory}${url}`;
    }).join('\n');
  }

  const subject = `🎯 NEW CITATION ORDER - ${packageSize} Citations for ${businessName}`;
  const emailBody = `
NEW CITATION BUILDING ORDER RECEIVED!

💰 ORDER DETAILS:
   • Package: ${packageSize} Citations
   • Amount Paid: $${(amountPaid / 100).toFixed(2)}
   • Order Date: ${new Date().toLocaleString()}

👤 CUSTOMER INFORMATION:
   • Name: ${customerName}
   • Email: ${customerEmail}

🏢 BUSINESS INFORMATION:
   • Business Name: ${businessName}
   • Address: ${businessAddress}
   • Phone: ${businessPhone}

📊 CITATION ANALYSIS:
   • Total Directories Analyzed: ${totalAnalyzed || 'Not analyzed'}
   • Missing Citations: ${missingCount || 0} (BUILD THESE FIRST!)
   • Existing Citations: ${foundCount || 0} (Skip these)

🎯 PRIORITY CITATIONS (Missing/RED - Build These First):
${priorityList}

✅ EXISTING CITATIONS (Found/GREEN - Skip These):
${existingList}

📋 ACTION REQUIRED:
1. Review the priority citations list above
2. Build citations for the ${missingCount || 0} missing directories FIRST
3. Then fill remaining slots (up to ${packageSize} total) with other high-value directories
4. Avoid duplicating the ${foundCount || 0} existing citations listed above

---
This order was placed through the Locality SEO Audit Tool.
  `.trim();

  try {
    // Method 1: Log to console (always works for debugging)
    console.log('📧 CITATION ORDER EMAIL NOTIFICATION:');
    console.log('To: trylocality@gmail.com');
    console.log('Subject:', subject);
    console.log('Body:', emailBody);

    // Send to webhook (try citation webhook first, then fall back to feedback webhook)
    const webhookUrl = process.env.CITATION_ORDER_WEBHOOK_URL || process.env.FEEDBACK_WEBHOOK_URL;
    if (webhookUrl) {
      const webhookData = {
        to: 'trylocality@gmail.com',
        subject: subject,
        body: emailBody,
        text: emailBody,
        orderData: orderData,
        type: 'citation_order',
        emailType: 'citation_order',
        timestamp: new Date().toISOString()
      };

      console.log(`🔗 Sending citation order notification to webhook: ${webhookUrl.substring(0, 50)}...`);

      await axios.post(webhookUrl, webhookData, {
        timeout: 5000,
        headers: { 'Content-Type': 'application/json' }
      });

      console.log('✅ Citation order webhook sent successfully');
    } else {
      console.warn('⚠️ No CITATION_ORDER_WEBHOOK_URL or FEEDBACK_WEBHOOK_URL configured');
    }

    return true;
  } catch (error) {
    console.error('❌ Citation order email sending failed:', error.message);
    // Don't throw error - we don't want to fail the order if email fails
    return false;
  }
}

// ==========================================
// BUSINESS ANALYSIS FUNCTIONS
// ==========================================

// Helper function to find best matching business from search results
function findBestMatch(businesses, searchName, searchLocation) {
  if (!businesses || businesses.length === 0) return null;
  
  // If only one result, return it
  if (businesses.length === 1) {
    return businesses[0];
  }
  
  console.log(`🔍 Finding best match for "${searchName}" in "${searchLocation}" from ${businesses.length} results`);
  
  let bestMatch = businesses[0];
  let bestScore = 0;
  
  for (const business of businesses) {
    let score = 0;
    const businessName = (business.name || '').toLowerCase();
    const businessAddress = (business.full_address || business.address || '').toLowerCase();
    const searchNameLower = searchName.toLowerCase();
    const searchLocationLower = searchLocation.toLowerCase();
    
    // Name matching (most important)
    if (businessName.includes(searchNameLower) || searchNameLower.includes(businessName)) {
      score += 10;
    }
    
    // Exact name match bonus
    if (businessName === searchNameLower) {
      score += 5;
    }
    
    // Location matching
    if (businessAddress.includes(searchLocationLower)) {
      score += 5;
    }
    
    // Prefer verified/claimed businesses
    if (business.verified || business.claimed) {
      score += 3;
    }
    
    // Prefer businesses with reviews
    if (business.reviews > 0) {
      score += 2;
    }
    
    console.log(`🔍 Business: ${business.name} | Address: ${businessAddress} | Score: ${score}`);
    
    if (score > bestScore) {
      bestScore = score;
      bestMatch = business;
    }
  }
  
  console.log(`✅ Best match selected: ${bestMatch.name} (Score: ${bestScore})`);
  return bestMatch;
}

// Function to get multiple business profiles for verification
async function getBusinessProfileOptions(businessName, location) {
  try {
    // Enhanced query for county-level searches
    const { city, state, isCounty } = extractCityState(location);
    let query;
    
    if (isCounty) {
      query = `${businessName} ${city} County ${state}`;
      console.log(`🔍 County-level profile search: ${query}`);
    } else {
      query = `${businessName} ${location}`;
      console.log(`🔍 Profile search: ${query}`);
    }
    
    if (!OUTSCRAPER_API_KEY) {
      throw new Error('Outscraper API key not configured');
    }
    
    // Detect country/region from location
    const { region, language } = detectCountryRegion(location);
    
    const response = await axios.get('https://api.outscraper.com/maps/search-v2', {
      params: {
        query: query,
        language: language,
        region: region,
        limit: 5  // Get up to 5 results for user selection
      },
      headers: {
        'X-API-KEY': OUTSCRAPER_API_KEY
      },
      timeout: 15000
    });
    
    console.log('🔍 Profile options response status:', response.status);
    
    // Handle async response
    if (response.status === 202 && response.data.status === 'Pending') {
      console.log('⏳ Profile search is async, polling for results...');
      
      const resultsUrl = response.data.results_location;
      
      // Poll for results (max 60 seconds - increased from 30)
      for (let i = 0; i < 12; i++) {
        await new Promise(resolve => setTimeout(resolve, 5000));
        
        try {
          const resultResponse = await axios.get(resultsUrl, {
            headers: {
              'X-API-KEY': OUTSCRAPER_API_KEY
            },
            timeout: 10000
          });
          
          if (resultResponse.data && resultResponse.data.data && resultResponse.data.data.length > 0) {
            const businessData = resultResponse.data.data[0];
            const businesses = Array.isArray(businessData) ? businessData : [businessData];
            return formatBusinessOptions(businesses);
          }
        } catch (pollError) {
          console.log(`⏳ Poll ${i + 1}: Still processing...`);
        }
      }
      
      throw new Error('Profile search timeout - no results after 30 seconds');
    }
    
    // Handle immediate response
    if (response.data && response.data.data && response.data.data.length > 0) {
      const businessData = response.data.data[0];
      const businesses = Array.isArray(businessData) ? businessData : [businessData];
      return formatBusinessOptions(businesses);
    }
    
    throw new Error('No business profiles found in search results');
    
  } catch (error) {
    console.error('❌ Profile options error:', error.message);
    throw new Error(`Failed to fetch profile options: ${error.message}`);
  }
}

// Helper function to format business options for frontend
function formatBusinessOptions(businesses) {
  return businesses.map((business, index) => ({
    id: index,
    name: business.name || business.title || 'Unknown Business',
    address: business.full_address || business.address || 'Address not available',
    phone: business.phone || 'Phone not available',
    rating: parseFloat(business.rating) || 0,
    reviews: parseInt(business.reviews) || parseInt(business.reviews_count) || 0,
    verified: business.verified || business.claimed || false,
    website: business.site || business.website || '',
    place_id: business.place_id || business.google_id,
    categories: business.subtypes ? business.subtypes.split(', ') : (business.type ? [business.type] : []),
    rawData: business  // Keep original data for report generation
  }));
}

// 1. OUTSCRAPER - Get primary business data
async function getOutscraperData(businessName, location) {
  try {
    // Check cache first (30 minute TTL - aligns with Google's indexing delay)
    const cacheKey = `outscraper_${businessName.toLowerCase()}_${location.toLowerCase()}`;
    try {
      const cached = await db.get(
        'SELECT data, created_at FROM api_cache WHERE cache_key = $1 AND expires_at > NOW()',
        [cacheKey]
      );

      if (cached) {
        const age = Math.round((Date.now() - new Date(cached.created_at)) / 1000 / 60);
        console.log(`✅ Using cached Outscraper data (age: ${age} minutes)`);
        return JSON.parse(cached.data);
      }
    } catch (cacheError) {
      console.log(`⚠️ Cache check failed: ${cacheError.message}`);
      // Continue to fetch fresh data
    }

    // Enhanced query for county-level searches
    const { city, state, isCounty } = extractCityState(location);
    let query;

    if (isCounty) {
      // For county searches, create a broader query that includes the county name
      query = `${businessName} ${city} County ${state}`;
      console.log(`🔍 County-level Outscraper search: ${query}`);
    } else {
      // Standard city, state query
      query = `${businessName} ${location}`;
      console.log(`🔍 Outscraper search: ${query}`);
    }

    if (!OUTSCRAPER_API_KEY) {
      throw new Error('Outscraper API key not configured');
    }

    // Detect country/region from location
    const { region, language } = detectCountryRegion(location);
    
    const response = await axios.get('https://api.outscraper.com/maps/search-v2', {
      params: {
        query: query,
        language: language,
        region: region,
        limit: 3  // Get top 3 results for better matching
      },
      headers: {
        'X-API-KEY': OUTSCRAPER_API_KEY
      },
      timeout: 15000
    });
    
    console.log('🔍 Outscraper response status:', response.status);
    
    // Handle async response
    if (response.status === 202 && response.data.status === 'Pending') {
      console.log('⏳ Outscraper job is async, polling for results...');
      
      const resultsUrl = response.data.results_location;
      
      // Poll for results (max 60 seconds - increased from 30)
      for (let i = 0; i < 12; i++) {
        await new Promise(resolve => setTimeout(resolve, 5000));
        
        try {
          const resultResponse = await axios.get(resultsUrl, {
            headers: {
              'X-API-KEY': OUTSCRAPER_API_KEY
            },
            timeout: 10000
          });
          
          console.log('🔍 POLL RESPONSE STRUCTURE:', typeof resultResponse.data.data, Array.isArray(resultResponse.data.data));
          if (resultResponse.data && resultResponse.data.data && resultResponse.data.data.length > 0) {
            const businessData = resultResponse.data.data[0];
            console.log('🔍 BUSINESS DATA TYPE:', typeof businessData, 'IS_ARRAY:', Array.isArray(businessData));
            
            // Handle if business data is an array (extract first element) or direct object
            const businesses = Array.isArray(businessData) ? businessData : [businessData];
            const business = findBestMatch(businesses, businessName, location);
            console.log(`✅ Outscraper found: ${business.name || business.title || businessName}`);
            console.log(`🔍 PROFILE DETAILS: Name: "${business.name}", Address: "${business.full_address || business.address}", Phone: "${business.phone}"`);
            console.log(`🔍 VERIFICATION STATUS: Verified: ${business.verified}, Claimed: ${business.claimed}, Rating: ${business.rating}, Reviews: ${business.reviews}`);
            console.log('🔍 FINAL BUSINESS OBJECT:', JSON.stringify(business, null, 2));

            const resultData = {
              name: business.name || business.title || businessName,
              phone: business.phone || '',
              address: business.full_address || business.address || '',
              website: business.site || business.website || '',
              rating: parseFloat(business.rating) || 0,
              reviews: parseInt(business.reviews) || parseInt(business.reviews_count) || 0,
              verified: business.verified || business.claimed || false,
              description: business.description || '',
              photos: parseInt(business.photos_count) || parseInt(business.photos) || 0,
              photos_count: parseInt(business.photos_count) || parseInt(business.photos) || 0,
              categories: business.subtypes ? business.subtypes.split(', ') : (business.type ? [business.type] : []),
              hours: business.working_hours || business.hours || {},
              place_id: business.place_id || business.google_id,
              google_id: business.google_id || business.place_id,
              reviews_link: business.reviews_link || '',
              social: {},
              posts: Array.isArray(business.posts) ? business.posts.length : 0,
              questionsAnswers: 0,
              photoCategories: []
            };

            // Cache the result for 30 minutes
            try {
              await db.query(
                'INSERT INTO api_cache (cache_key, data, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'30 minutes\') ON CONFLICT (cache_key) DO UPDATE SET data = $2, expires_at = NOW() + INTERVAL \'30 minutes\'',
                [cacheKey, JSON.stringify(resultData)]
              );
              console.log(`💾 Outscraper data cached for 30 minutes`);
            } catch (cacheInsertError) {
              console.log(`⚠️ Failed to cache Outscraper data: ${cacheInsertError.message}`);
            }

            return resultData;
          }
        } catch (pollError) {
          console.log(`⏳ Poll ${i + 1}: Still processing...`);
        }
      }
      
      throw new Error('Outscraper polling timeout - no results after 60 seconds');
    }
    
    // Handle immediate response
    if (response.data && response.data.data && response.data.data.length > 0) {
      const businessData = response.data.data[0];
      console.log('🔍 IMMEDIATE BUSINESS DATA TYPE:', typeof businessData, 'IS_ARRAY:', Array.isArray(businessData));
      
      // Handle if business data is an array (extract first element) or direct object
      const businesses = Array.isArray(businessData) ? businessData : [businessData];
      const business = findBestMatch(businesses, businessName, location);
      console.log(`✅ Outscraper found: ${business.name || business.title || businessName}`);
      console.log(`🔍 PROFILE DETAILS: Name: "${business.name}", Address: "${business.full_address || business.address}", Phone: "${business.phone}"`);
      console.log(`🔍 VERIFICATION STATUS: Verified: ${business.verified}, Claimed: ${business.claimed}, Rating: ${business.rating}, Reviews: ${business.reviews}`);

      const resultData = {
        name: business.name || business.title || businessName,
        phone: business.phone || '',
        address: business.full_address || business.address || '',
        website: business.site || business.website || '',
        rating: parseFloat(business.rating) || 0,
        reviews: parseInt(business.reviews) || parseInt(business.reviews_count) || 0,
        verified: business.verified || business.claimed || false,
        description: business.description || '',
        photos: parseInt(business.photos_count) || parseInt(business.photos) || 0,
        photos_count: parseInt(business.photos_count) || parseInt(business.photos) || 0,
        categories: business.subtypes ? business.subtypes.split(', ') : (business.type ? [business.type] : []),
        hours: business.working_hours || business.hours || {},
        place_id: business.place_id || business.google_id,
        google_id: business.google_id || business.place_id,
        reviews_link: business.reviews_link || '',
        social: {},
        posts: Array.isArray(business.posts) ? business.posts.length : 0,
        questionsAnswers: 0,
        photoCategories: []
      };

      // Cache the result for 30 minutes
      try {
        await db.query(
          'INSERT INTO api_cache (cache_key, data, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'30 minutes\') ON CONFLICT (cache_key) DO UPDATE SET data = $2, expires_at = NOW() + INTERVAL \'30 minutes\'',
          [cacheKey, JSON.stringify(resultData)]
        );
        console.log(`💾 Outscraper data cached for 30 minutes`);
      } catch (cacheInsertError) {
        console.log(`⚠️ Failed to cache Outscraper data: ${cacheInsertError.message}`);
      }

      return resultData;
    }

    throw new Error('No business found in Outscraper response');
    
  } catch (error) {
    console.error('❌ Outscraper error:', error.message);
    throw new Error(`Outscraper failed: ${error.message}`);
  }
}
// 2. SCRAPINGBEE SCREENSHOT - For visual analysis
async function takeBusinessProfileScreenshot(businessName, location, placeId = null) {
  try {
    console.log(`📸 Taking ScrapingBee screenshot: ${businessName}${placeId ? ' (using place_id)' : ''}`);

    await ensureScreenshotsDir();

    if (!SCRAPINGBEE_API_KEY) {
      throw new Error('ScrapingBee API key not configured');
    }

    // Check cache first (30 minute TTL - aligns with Google's indexing delay)
    const cacheKey = `${businessName.toLowerCase()}_${location.toLowerCase()}`;
    try {
      const cached = await db.get(
        'SELECT filepath, filename, created_at FROM screenshot_cache WHERE cache_key = $1 AND expires_at > NOW()',
        [cacheKey]
      );

      if (cached) {
        // Verify file still exists
        try {
          await fs.access(cached.filepath);
          const age = Math.round((Date.now() - new Date(cached.created_at)) / 1000 / 60);
          console.log(`✅ Using cached screenshot (age: ${age} minutes)`);
          return {
            success: true,
            filename: cached.filename,
            filepath: cached.filepath,
            url: `/screenshots/${cached.filename}`,
            fromCache: true
          };
        } catch (fileError) {
          console.log(`⚠️ Cached screenshot file missing, will regenerate`);
          // Delete stale cache entry
          await db.query('DELETE FROM screenshot_cache WHERE cache_key = $1', [cacheKey]);
        }
      }
    } catch (cacheError) {
      console.log(`⚠️ Cache check failed: ${cacheError.message}`);
      // Continue to generate new screenshot
    }

    // Detect location for better screenshot results
    const { region } = detectCountryRegion(location);
    const googleDomain = region === 'AE' ? 'google.ae' : region === 'GB' ? 'google.co.uk' : 'google.com';

    // Use direct Google Maps URL with place_id if available (better for product tiles visibility)
    // Otherwise fall back to search results
    let targetUrl;
    if (placeId) {
      targetUrl = `https://www.${googleDomain}/maps/search/?api=1&query=${encodeURIComponent(businessName)}&query_place_id=${placeId}`;
      console.log(`🎯 Using direct Maps URL with place_id for better product tile visibility`);
    } else {
      // Fallback to search if no place_id
      const { city, state, isCounty } = extractCityState(location);
      const searchQuery = isCounty ? `${businessName} ${city} County ${state}` : `${businessName} ${location}`;
      targetUrl = `https://www.${googleDomain}/search?q=${encodeURIComponent(searchQuery)}&gl=${region.toLowerCase()}&hl=en`;
      console.log(`⚠️ No place_id available, using search results (product tiles may not be visible)`);
    }

    const params = {
      api_key: SCRAPINGBEE_API_KEY,
      url: targetUrl,
      custom_google: 'true',
      stealth_proxy: 'true',
      render_js: 'true',
      screenshot: 'true',
      screenshot_full_page: 'true',
      wait: 4000,
      window_width: 1920,
      window_height: 1080,
      block_resources: 'false',
      country_code: region.toLowerCase()
    };

    const response = await axios.get('https://app.scrapingbee.com/api/v1/', {
      params: params,
      timeout: 120000,
      responseType: 'arraybuffer'
    });

    if (response.status === 200 && response.headers['content-type'].includes('image')) {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const safeBusinessName = businessName.replace(/[^a-zA-Z0-9]/g, '_');
      const filename = `${safeBusinessName}_${timestamp}.png`;
      const filepath = path.join(screenshotsDir, filename);

      await fs.writeFile(filepath, response.data);

      console.log(`✅ Screenshot saved: ${filename}`);

      // Cache the screenshot for 30 minutes
      try {
        await db.query(
          'INSERT INTO screenshot_cache (cache_key, filepath, filename, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL \'30 minutes\')',
          [cacheKey, filepath, filename]
        );
        console.log(`💾 Screenshot cached for 30 minutes`);
      } catch (cacheInsertError) {
        console.log(`⚠️ Failed to cache screenshot: ${cacheInsertError.message}`);
        // Don't fail the request if caching fails
      }

      return {
        success: true,
        filename: filename,
        filepath: filepath,
        url: `/screenshots/${filename}`,
        fileSize: response.data.length,
        fromCache: false
      };
    } else {
      throw new Error(`Unexpected response: ${response.status}`);
    }

  } catch (error) {
    console.error('❌ Screenshot error:', error.message);
    throw new Error(`Screenshot failed: ${error.message}`);
  }
}

// 2C. TAKE SERVICES TAB SCREENSHOT - Capture the Services section specifically
async function takeServicesTabScreenshot(businessName, location, placeId = null) {
  try {
    console.log(`📋 Taking Services tab screenshot: ${businessName}`);

    await ensureScreenshotsDir();

    if (!SCRAPINGBEE_API_KEY) {
      throw new Error('ScrapingBee API key not configured');
    }

    if (!placeId) {
      console.log(`⚠️ No place_id available - cannot navigate to Services tab directly`);
      return null;
    }

    // Check cache first (30 minute TTL)
    const cacheKey = `services_${businessName.toLowerCase()}_${location.toLowerCase()}`;
    try {
      const cached = await db.get(
        'SELECT filepath, filename, created_at FROM screenshot_cache WHERE cache_key = $1 AND expires_at > NOW()',
        [cacheKey]
      );

      if (cached) {
        try {
          await fs.access(cached.filepath);
          const age = Math.round((Date.now() - new Date(cached.created_at)) / 1000 / 60);
          console.log(`✅ Using cached Services screenshot (age: ${age} minutes)`);
          return {
            success: true,
            filename: cached.filename,
            filepath: cached.filepath,
            url: `/screenshots/${cached.filename}`,
            fromCache: true
          };
        } catch (fileError) {
          console.log(`⚠️ Cached Services screenshot missing, will regenerate`);
          await db.query('DELETE FROM screenshot_cache WHERE cache_key = $1', [cacheKey]);
        }
      }
    } catch (cacheError) {
      console.log(`⚠️ Services screenshot cache check failed: ${cacheError.message}`);
    }

    // Detect location
    const { region } = detectCountryRegion(location);
    const googleDomain = region === 'AE' ? 'google.ae' : region === 'GB' ? 'google.co.uk' : 'google.com';

    // Google Maps URL that opens directly to the place with Services tab
    // We'll use JavaScript execution to click the Services tab
    const targetUrl = `https://www.${googleDomain}/maps/place/?q=place_id:${placeId}`;

    const params = {
      api_key: SCRAPINGBEE_API_KEY,
      url: targetUrl,
      custom_google: 'true',
      stealth_proxy: 'true',
      render_js: 'true',
      screenshot: 'true',
      screenshot_full_page: 'false', // Don't need full page for Services
      wait: 5000, // Wait longer for tabs to load
      window_width: 1920,
      window_height: 1080,
      block_resources: 'false',
      country_code: region.toLowerCase(),
      // Click on Services tab using JavaScript
      js_snippet: "try { const servicesTab = document.querySelector('button[aria-label*=\"Services\"], button[data-tab-index=\"1\"], button:has-text(\"Services\")'); if (servicesTab) { servicesTab.click(); await new Promise(r => setTimeout(r, 2000)); } } catch(e) { console.log('Services tab not found'); }"
    };

    const response = await axios.get('https://app.scrapingbee.com/api/v1/', {
      params: params,
      timeout: 120000,
      responseType: 'arraybuffer'
    });

    if (response.status === 200 && response.headers['content-type'].includes('image')) {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const safeBusinessName = businessName.replace(/[^a-zA-Z0-9]/g, '_');
      const filename = `${safeBusinessName}_services_${timestamp}.png`;
      const filepath = path.join(screenshotsDir, filename);

      await fs.writeFile(filepath, response.data);

      console.log(`✅ Services screenshot saved: ${filename}`);

      // Cache for 30 minutes
      try {
        await db.query(
          'INSERT INTO screenshot_cache (cache_key, filepath, filename, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL \'30 minutes\')',
          [cacheKey, filepath, filename]
        );
        console.log(`💾 Services screenshot cached for 30 minutes`);
      } catch (cacheInsertError) {
        console.log(`⚠️ Failed to cache Services screenshot: ${cacheInsertError.message}`);
      }

      return {
        success: true,
        filename: filename,
        filepath: filepath,
        url: `/screenshots/${filename}`
      };
    } else {
      throw new Error(`Unexpected response: ${response.status}`);
    }

  } catch (error) {
    console.error('❌ Services screenshot error:', error.message);
    // Non-critical error - return null and continue
    return null;
  }
}

// 2B. SCRAPE SOCIAL LINKS FROM GBP HTML - Get social links from the actual GBP page
async function scrapeSocialLinksFromGBP(businessName, location, placeId = null) {
  try {
    console.log(`🔗 Scraping social links from GBP HTML: ${businessName}`);

    if (!SCRAPINGBEE_API_KEY) {
      console.log(`⚠️ ScrapingBee API key not configured, skipping social link scraping`);
      return { count: 0, meets2Plus: false, platforms: [] };
    }

    // Detect location for better results
    const { region } = detectCountryRegion(location);
    const googleDomain = region === 'AE' ? 'google.ae' : region === 'GB' ? 'google.co.uk' : 'google.com';

    // Build target URL - prefer place_id for accuracy
    let targetUrl;
    if (placeId) {
      targetUrl = `https://www.${googleDomain}/maps/search/?api=1&query=${encodeURIComponent(businessName)}&query_place_id=${placeId}`;
    } else {
      const { city, state, isCounty } = extractCityState(location);
      const searchQuery = isCounty ? `${businessName} ${city} County ${state}` : `${businessName} ${location}`;
      targetUrl = `https://www.${googleDomain}/search?q=${encodeURIComponent(searchQuery)}&gl=${region.toLowerCase()}&hl=en`;
    }

    const params = {
      api_key: SCRAPINGBEE_API_KEY,
      url: targetUrl,
      custom_google: 'true',
      stealth_proxy: 'true',
      render_js: 'true',
      wait: 4000,
      country_code: region.toLowerCase()
    };

    const response = await axios.get('https://app.scrapingbee.com/api/v1/', {
      params: params,
      timeout: 45000  // Reduced from 60s to 45s
    });

    if (response.status === 200 && response.data) {
      const htmlContent = typeof response.data === 'string' ? response.data : response.data.toString();
      const htmlLower = htmlContent.toLowerCase();

      // Look for social media links in the HTML
      const socialPlatforms = [
        { name: 'Facebook', patterns: [/https?:\/\/(?:www\.)?facebook\.com\/[a-zA-Z0-9._-]+/gi, /https?:\/\/(?:www\.)?fb\.com\/[a-zA-Z0-9._-]+/gi] },
        { name: 'Instagram', patterns: [/https?:\/\/(?:www\.)?instagram\.com\/[a-zA-Z0-9._-]+/gi] },
        { name: 'Twitter', patterns: [/https?:\/\/(?:www\.)?(?:twitter|x)\.com\/[a-zA-Z0-9._-]+/gi] },
        { name: 'LinkedIn', patterns: [/https?:\/\/(?:www\.)?linkedin\.com\/(?:company|in)\/[a-zA-Z0-9._-]+/gi] },
        { name: 'YouTube', patterns: [/https?:\/\/(?:www\.)?youtube\.com\/(?:channel|c|user)\/[a-zA-Z0-9._-]+/gi] },
        { name: 'TikTok', patterns: [/https?:\/\/(?:www\.)?tiktok\.com\/@[a-zA-Z0-9._-]+/gi] },
        { name: 'Pinterest', patterns: [/https?:\/\/(?:www\.)?pinterest\.com\/[a-zA-Z0-9._-]+/gi] }
      ];

      const foundPlatforms = [];
      const foundLinks = {};

      socialPlatforms.forEach(platform => {
        platform.patterns.forEach(pattern => {
          const matches = htmlContent.match(pattern);
          if (matches && matches.length > 0) {
            // Get unique, clean URLs
            const uniqueUrls = [...new Set(matches.map(url => {
              // Clean up URLs (remove tracking params, etc.)
              return url.split('?')[0].split('&')[0];
            }))];

            if (!foundPlatforms.includes(platform.name)) {
              foundPlatforms.push(platform.name);
              foundLinks[platform.name] = uniqueUrls[0]; // Store first unique URL
            }
          }
        });
      });

      const count = foundPlatforms.length;
      const meets2Plus = count >= 2;

      console.log(`  ${meets2Plus ? '✅' : '❌'} Found ${count} social platform${count !== 1 ? 's' : ''}: ${foundPlatforms.join(', ') || 'none'}`);

      return {
        count: count,
        meets2Plus: meets2Plus,
        platforms: foundPlatforms,
        links: foundLinks
      };
    } else {
      console.log(`  ⚠️ Unexpected response status: ${response.status}`);
      return { count: 0, meets2Plus: false, platforms: [] };
    }

  } catch (error) {
    console.error(`  ❌ Social link scraping error: ${error.message}`);
    // Return empty result rather than throwing - this is non-critical
    return { count: 0, meets2Plus: false, platforms: [] };
  }
}

// 3. AI ANALYSIS - Extract posts, services, Q&As from screenshot
async function analyzeScreenshotWithAI(screenshotPath, businessName) {
  try {
    console.log(`🤖 AI analyzing screenshot: ${businessName}`);
    
    if (!OPENAI_API_KEY) {
      throw new Error('OpenAI API key not configured');
    }
    
    const imageBuffer = await fs.readFile(screenshotPath);
    const base64Image = imageBuffer.toString('base64');
    
    const analysisPrompt = `
    Analyze this Google Business Profile screenshot for "${businessName}" and extract these 7 key factors.
    Look very carefully at ALL visible sections of the profile.

    IMPORTANT: Look for these specific elements:

    1. BUSINESS DESCRIPTION: The "About" or "From the business" section
       - Check if description exists and estimate character length
       - Determine if it's 150+ characters

    2. CATEGORIES: Business categories/types listed
       - Count how many categories/subcategories are shown
       - Look for primary category + additional categories

    3. PHOTOS: Photo count (usually shown as a number)
       - Look for photo gallery section with count displayed

    4. REVIEWS: Review count and average rating
       - Find the star rating and number of reviews
       - Usually shown prominently near business name

    5. PRODUCT/SERVICE TILES: Products or Services section
       - Look for dedicated "Products" or "Services" section with tiles/cards
       - Count individual product/service listings

    6. GOOGLE POSTS: Recent posts in the "Posts" or "Updates" section
       - Check if any posts are visible
       - Try to determine if most recent post is within last 15 days
       - Look for date indicators like "1d ago", "5d ago", "2w ago"

    7. SOCIAL LINKS: Social media profile links
       - Look for social media icons (Facebook, Instagram, Twitter, LinkedIn, etc.)
       - Usually in business info section

    NOTE: Q&A section has been removed from Google Business Profiles - do not look for it.

    Respond ONLY with valid JSON in this EXACT format:
    {
      "description": {
        "exists": false,
        "estimatedLength": 0,
        "meets150Chars": false
      },
      "categories": {
        "count": 0,
        "meets3Plus": false,
        "visible": []
      },
      "photos": {
        "count": 0,
        "meets10Plus": false
      },
      "reviews": {
        "count": 0,
        "rating": 0.0,
        "meets15Plus": false,
        "meetsRating4Plus": false
      },
      "productTiles": {
        "count": 0,
        "meets2Plus": false
      },
      "posts": {
        "hasAny": false,
        "count": 0,
        "mostRecentDaysAgo": null,
        "meetsLast15Days": false
      },
      "socialLinks": {
        "count": 0,
        "meets2Plus": false,
        "platforms": []
      }
    }
    `;

    const openaiResponse = await axios.post('https://api.openai.com/v1/chat/completions', {
      model: 'gpt-4o',
      messages: [{
        role: 'user',
        content: [{
          type: 'text',
          text: analysisPrompt
        }, {
          type: 'image_url',
          image_url: {
            url: `data:image/png;base64,${base64Image}`,
            detail: 'high'
          }
        }]
      }],
      max_tokens: 800
    }, {
      headers: {
        'Authorization': `Bearer ${OPENAI_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    const aiResponse = openaiResponse.data.choices[0].message.content;
    let cleanedResponse = aiResponse.trim();

    // Clean markdown formatting
    if (cleanedResponse.startsWith('```json')) {
      cleanedResponse = cleanedResponse.replace(/^```json\s*/, '');
    }
    if (cleanedResponse.endsWith('```')) {
      cleanedResponse = cleanedResponse.replace(/\s*```$/, '');
    }

    const analysis = JSON.parse(cleanedResponse);

    console.log(`✅ AI Analysis Complete:`, {
      description: analysis.description?.meets150Chars,
      categories: `${analysis.categories?.count} (3+: ${analysis.categories?.meets3Plus})`,
      photos: `${analysis.photos?.count} (10+: ${analysis.photos?.meets10Plus})`,
      reviews: `${analysis.reviews?.count} reviews, ${analysis.reviews?.rating}⭐`,
      products: `${analysis.productTiles?.count} (2+: ${analysis.productTiles?.meets2Plus})`,
      posts: `${analysis.posts?.count} (last 15d: ${analysis.posts?.meetsLast15Days})`,
      social: `${analysis.socialLinks?.count} (2+: ${analysis.socialLinks?.meets2Plus})`,
      qa: `${analysis.qa?.count} (2+: ${analysis.qa?.meets2Plus})`
    });

    return analysis;
    
  } catch (error) {
    console.error('❌ AI analysis error:', error.message);
    throw new Error(`AI analysis failed: ${error.message}`);
  }
}

// SERVICES TAB ANALYSIS - Analyze Services section from screenshot
async function analyzeServicesFromScreenshot(screenshotPath, businessName) {
  try {
    console.log(`🛠️ AI analyzing Services tab screenshot: ${businessName}`);

    if (!OPENAI_API_KEY) {
      throw new Error('OpenAI API key not configured');
    }

    const imageData = await fs.readFile(screenshotPath);
    const base64Image = imageData.toString('base64');

    const prompt = `Analyze this Google Business Profile Services tab screenshot.

Business: ${businessName}

Look for the Services section and determine:
1. Does a Services section/tab exist?
2. How many individual services are listed/visible?
3. Do the services appear to have descriptions (not just titles)?

Respond ONLY with valid JSON in this EXACT format:
{
  "hasServices": true/false,
  "servicesCount": 0,
  "hasDescriptions": true/false,
  "servicesVisible": ["Service 1", "Service 2"]
}

Notes:
- If no Services section is visible, set hasServices to false and servicesCount to 0
- Count ALL visible service items
- Check if services have description text below the title
- Include up to 5 service names in servicesVisible array`;

    const response = await openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [
        {
          role: 'user',
          content: [
            { type: 'text', text: prompt },
            {
              type: 'image_url',
              image_url: {
                url: `data:image/png;base64,${base64Image}`,
                detail: 'high'
              }
            }
          ]
        }
      ],
      max_tokens: 300,
      temperature: 0.1
    });

    const content = response.choices[0].message.content.trim();

    let cleanedResponse = content;
    if (content.includes('```json')) {
      cleanedResponse = content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    } else if (content.includes('```')) {
      cleanedResponse = content.replace(/```\n?/g, '').trim();
    }

    const analysis = JSON.parse(cleanedResponse);

    console.log(`✅ Services Analysis:`, {
      hasServices: analysis.hasServices,
      count: analysis.servicesCount,
      hasDescriptions: analysis.hasDescriptions,
      examples: analysis.servicesVisible?.slice(0, 3)
    });

    return analysis;

  } catch (error) {
    console.error('❌ Services analysis error:', error.message);
    // Return safe fallback
    return {
      hasServices: false,
      servicesCount: 0,
      hasDescriptions: false,
      servicesVisible: [],
      error: error.message
    };
  }
}

// BUSINESS NAME KEYWORD ANALYSIS - Check if business name contains industry keywords
async function analyzeBusinessNameKeywords(businessName, industry) {
  try {
    console.log(`🏷️ Analyzing business name keywords: "${businessName}" in ${industry}`);

    const prompt = `Analyze if this business name includes relevant industry keywords.

Business Name: "${businessName}"
Industry: "${industry}"

Task: Determine if the business name contains keywords that customers would search for when looking for this type of business.

Examples:
- "Joe's Plumbing & Heating" → HAS keywords (plumbing, heating)
- "ABC Services" → NO keywords
- "Sam's Sales Recruiting" → HAS keywords (sales, recruiting)
- "TechDraft Solutions" → NO keywords (for recruiting industry)

Respond ONLY with valid JSON in this exact format:
{
  "hasKeywords": true/false,
  "matchedKeywords": ["keyword1", "keyword2"],
  "missingKeywords": ["keyword3"],
  "confidence": "high/medium/low"
}`;

    const response = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        {
          role: 'user',
          content: prompt
        }
      ],
      temperature: 0.3,
      max_tokens: 200
    });

    const content = response.choices[0].message.content.trim();

    // Remove markdown code blocks if present
    let cleanedResponse = content;
    if (content.includes('```json')) {
      cleanedResponse = content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    } else if (content.includes('```')) {
      cleanedResponse = content.replace(/```\n?/g, '').trim();
    }

    const analysis = JSON.parse(cleanedResponse);

    console.log(`✅ Keyword Analysis:`, {
      hasKeywords: analysis.hasKeywords,
      matched: analysis.matchedKeywords,
      missing: analysis.missingKeywords
    });

    return analysis;

  } catch (error) {
    console.error('❌ Business name keyword analysis error:', error.message);
    // Return safe fallback
    return {
      hasKeywords: false,
      matchedKeywords: [],
      missingKeywords: [],
      confidence: 'low',
      error: error.message
    };
  }
}

// 4. CITATION CHECKER - Check presence in major directories
async function checkCitations(businessName, phoneNumber) {
  try {
    console.log(`🔍 Checking citations: ${businessName} with phone ${phoneNumber}`);
    
    if (!SERPAPI_KEY) {
      throw new Error('SerpAPI key not configured');
    }
    
    // Generate phone number search patterns for flexible matching
    const phonePatterns = generatePhoneSearchPatterns(phoneNumber);
    if (phonePatterns.length === 0) {
      console.warn('⚠️ No valid phone patterns generated, using business name only');
    }
    
    const directories = [
      { name: 'Angi', domain: 'angi.com' },
      { name: 'Apple Maps Business Connect', domain: 'mapsconnect.apple.com' },
      { name: 'Better Business Bureau', domain: 'bbb.org' },
      { name: 'Bing Places', domain: 'bing.com/maps' },
      { name: 'Chamber of Commerce', domain: 'chamberofcommerce.com' },
      { name: 'DNB (Dun & Bradstreet)', domain: 'dnb.com' },
      { name: 'Facebook', domain: 'facebook.com' },
      { name: 'Foursquare', domain: 'foursquare.com' },
      { name: 'Nextdoor', domain: 'nextdoor.com' },
      { name: 'Yelp', domain: 'yelp.com' }
    ];
    
    const found = [];
    const checked = [];

    // PERFORMANCE OPTIMIZATION: Check all directories in parallel instead of sequential
    const citationPromises = directories.map(async (directory, index) => {
      // Stagger requests by 100ms to avoid hitting rate limits
      await new Promise(resolve => setTimeout(resolve, index * 100));

      try {
        // Create search query with business name and phone patterns
        let searchQuery;
        if (phonePatterns.length > 0) {
          // Use the most common phone pattern (first one) for the search
          const primaryPhone = phonePatterns[0];
          searchQuery = `site:${directory.domain} "${businessName}" "${primaryPhone}"`;
        } else {
          // Fallback to name only if no phone patterns
          searchQuery = `site:${directory.domain} "${businessName}"`;
        }

        // Use US as default region for citations
        const googleDomain = 'google.com';

        const response = await axios.get('https://serpapi.com/search.json', {
          params: {
            engine: 'google',
            q: searchQuery,
            api_key: SERPAPI_KEY,
            num: 5, // Get more results to check phone number matches
            google_domain: googleDomain,
            gl: 'us',
            hl: 'en'
          },
          timeout: 8000  // Reduced from 10000ms to 8000ms
        });

        // Enhanced validation: check if results contain both business name and phone number
        let hasValidResults = false;
        let bestResult = null;

        if (response.data.organic_results && response.data.organic_results.length > 0) {
          for (const result of response.data.organic_results) {
            const resultText = `${result.title || ''} ${result.snippet || ''}`.toLowerCase();
            const businessNameFound = resultText.includes(businessName.toLowerCase());

            // Check if any phone pattern matches the result text
            let phoneFound = false;
            if (phonePatterns.length > 0) {
              phoneFound = phonePatterns.some(pattern =>
                resultText.includes(pattern.toLowerCase()) ||
                resultText.includes(normalizePhoneNumber(pattern))
              );
            } else {
              // If no phone provided, just check business name
              phoneFound = true;
            }

            if (businessNameFound && phoneFound) {
              hasValidResults = true;
              bestResult = result;
              break;
            }
          }
        }

        const checkedResult = {
          directory: directory.name,
          domain: directory.domain,
          found: hasValidResults,
          searchQuery: searchQuery,
          matchType: hasValidResults ? 'name+phone' : 'none'
        };

        const foundResult = hasValidResults && bestResult ? {
          directory: directory.name,
          domain: directory.domain,
          url: bestResult.link,
          title: bestResult.title,
          matchType: 'name+phone'
        } : null;

        return { checkedResult, foundResult };

      } catch (dirError) {
        console.error(`❌ Citation check failed for ${directory.name}:`, dirError.message);
        return {
          checkedResult: {
            directory: directory.name,
            domain: directory.domain,
            found: false,
            error: dirError.message
          },
          foundResult: null
        };
      }
    });

    // Wait for all citation checks to complete in parallel
    const citationResults = await Promise.allSettled(citationPromises);

    // Collect results
    citationResults.forEach(result => {
      if (result.status === 'fulfilled' && result.value) {
        checked.push(result.value.checkedResult);
        if (result.value.foundResult) {
          found.push(result.value.foundResult);
        }
      }
    });
    
    console.log(`📊 Citations found: ${found.length}/${directories.length}`);
    
    return {
      found: found,
      checked: checked,
      total: directories.length,
      stats: {
        found: found.length,
        missing: directories.length - found.length,
        percentage: Math.round((found.length / directories.length) * 100),
        score: found.length // 1 point per citation found
      }
    };
    
  } catch (error) {
    console.error('❌ Citation check error:', error.message);
    throw new Error(`Citation check failed: ${error.message}`);
  }
}

// 5. WEBSITE ANALYSIS - Check for GBP embed and get content for smart suggestions
async function analyzeWebsite(websiteUrl, location) {
  try {
    console.log(`🌐 Analyzing website: ${websiteUrl}`);

    if (!websiteUrl) {
      return {
        hasGBPEmbed: false,
        hasLocalizedPage: false,
        services: [],
        content: '',
        note: 'No website provided'
      };
    }

    // Ensure URL has protocol
    if (!websiteUrl.startsWith('http')) {
      websiteUrl = 'https://' + websiteUrl;
    }

    // Parse base URL for multi-page checking
    const baseUrl = new URL(websiteUrl).origin;

    // Define common pages to check for Google Maps embed
    const pagesToCheck = [
      websiteUrl, // Homepage
      `${baseUrl}/contact`,
      `${baseUrl}/contact-us`,
      `${baseUrl}/about`,
      `${baseUrl}/about-us`,
      `${baseUrl}/locations`,
      `${baseUrl}/location`
    ];

    // Check for GBP embed indicators
    const gbpIndicators = [
      'maps.google.com/maps',
      'google.com/maps/embed',
      'maps/embed',
      'place_id=',
      'maps.googleapis.com'
    ];

    let hasGBPEmbed = false;
    let htmlContent = '';
    let htmlLower = '';
    let checkedPages = 0;

    // Try to fetch homepage first
    try {
      console.log(`  📄 Checking homepage for GBP embed...`);
      const response = await axios.get(websiteUrl, {
        timeout: 10000,
        maxRedirects: 3,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      });

      htmlContent = response.data;
      htmlLower = htmlContent.toLowerCase();
      hasGBPEmbed = gbpIndicators.some(indicator => htmlLower.includes(indicator));
      checkedPages++;

      if (hasGBPEmbed) {
        console.log(`  ✅ Found GBP embed on homepage`);
      }
    } catch (error) {
      console.log(`  ⚠️ Could not fetch homepage: ${error.message}`);
    }

    // If not found on homepage, check other common pages
    if (!hasGBPEmbed) {
      console.log(`  🔍 GBP embed not on homepage, checking other pages...`);

      for (const pageUrl of pagesToCheck.slice(1)) { // Skip first (homepage) as we already checked
        try {
          const response = await axios.get(pageUrl, {
            timeout: 8000,
            maxRedirects: 3,
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
          });

          const pageHtml = response.data.toLowerCase();
          const foundOnThisPage = gbpIndicators.some(indicator => pageHtml.includes(indicator));
          checkedPages++;

          if (foundOnThisPage) {
            hasGBPEmbed = true;
            const pageName = pageUrl.replace(baseUrl, '');
            console.log(`  ✅ Found GBP embed on ${pageName}`);
            // Use this page's HTML for further analysis if homepage failed
            if (!htmlContent) {
              htmlContent = response.data;
              htmlLower = pageHtml;
            }
            break;
          }
        } catch (error) {
          // Silently continue to next page
        }
      }

      if (!hasGBPEmbed) {
        console.log(`  ❌ No GBP embed found on ${checkedPages} pages checked`);
      }
    }

    // If we still don't have HTML content, we can't continue analysis
    if (!htmlContent) {
      return {
        hasGBPEmbed: false,
        hasLocalizedPage: false,
        services: [],
        content: '',
        note: 'Website not accessible'
      };
    }
    
    // Check for localized landing page - search for both city AND state/country
    const { city, state } = extractCityState(location);
    const cityLower = city.toLowerCase();
    const stateLower = state.toLowerCase();
    
    // For international addresses, also check for country-specific patterns
    const locationParts = location.toLowerCase().split(/[,\-]/).map(p => p.trim());
    
    // First, extract all links from the page to check for location pages
    const linkPattern = /<a[^>]*href=["']([^"']+)["'][^>]*>/gi;
    const links = [];
    let match;
    while ((match = linkPattern.exec(htmlContent)) !== null) {
      links.push(match[1].toLowerCase());
    }
    
    // Check if site has location directory structure (like /locations/)
    const locationDirectoryPatterns = [
      /\/locations?\//,
      /\/service-areas?\//,
      /\/areas?\//,
      /\/cities\//,
      /\/serving\//,
      /\/serve\//,
      /\/where-we-serve\//,
      /\/coverage\//,
      /\/regions?\//
    ];
    
    const hasLocationDirectory = links.some(link => 
      locationDirectoryPatterns.some(pattern => pattern.test(link))
    );
    
    // URL-based patterns - looking for dedicated location pages
    const localizedIndicators = [
      // Direct location URLs
      `/${cityLower}/`,
      `/${cityLower}.html`,
      `/${cityLower}.php`,
      `/${cityLower}-`,
      `-${cityLower}-`,
      `-${cityLower}/`,
      
      // Location directory structures
      `/location/${cityLower}`,
      `/locations/${cityLower}`,
      `/service-area/${cityLower}`,
      `/service-areas/${cityLower}`,
      `/areas/${cityLower}`,
      `/cities/${cityLower}`,
      `/serving/${cityLower}`,
      `/serve/${cityLower}`,
      
      // Common patterns like "provo-custom-home-builder"
      `${cityLower}-custom-`,
      `${cityLower}-home-`,
      `${cityLower}-house-`,
      `${cityLower}-residential-`,
      `${cityLower}-commercial-`,
      `${cityLower}-builder`,
      `${cityLower}-contractor`,
      `${cityLower}-construction`,
      `${cityLower}-service`,
      
      // State-based URLs (avoid short abbreviations that could match other things)
      ...(stateLower.length > 2 ? [
        `/${stateLower}/`,
        `/${stateLower}.html`,
        `/${stateLower}.php`,
        `/location/${stateLower}`,
        `/locations/${stateLower}`,
        `/service-area/${stateLower}`,
        `/areas/${stateLower}`
      ] : []),
      
      // Multi-word location parts (counties, regions) - must be 4+ chars to avoid false matches
      ...locationParts
        .filter(part => part.length > 3 && !part.match(/^[a-z]{2}$/)) // Exclude 2-letter abbreviations
        .flatMap(part => [
          `/${part}/`,
          `/${part}.html`,
          `/${part}.php`,
          `/${part}-`,
          `/location/${part}`,
          `/locations/${part}`,
          `/service-area/${part}`,
          `/areas/${part}`,
          `${part}-custom-`,
          `${part}-home-`,
          `${part}-builder`
        ])
    ];
    
    // Check current page content, linked pages, or if site has location directory
    const hasLocalizedPage = hasLocationDirectory || 
      localizedIndicators.some(indicator => htmlLower.includes(indicator)) ||
      links.some(link => localizedIndicators.some(indicator => link.includes(indicator)));
    
    // Extract services for smart suggestions
    const services = extractServicesFromHTML(htmlContent);
    
    console.log(`${hasGBPEmbed ? '✅' : '❌'} GBP Embed | ${hasLocalizedPage ? '✅' : '❌'} Localized Page | ${services.length} services found`);
    if (hasLocationDirectory) {
      console.log(`✅ Found location directory structure on website`);
    }
    if (hasLocalizedPage && !hasLocationDirectory) {
      console.log(`✅ Found localized page references for ${city}`);
    }
    
    return {
      hasGBPEmbed: hasGBPEmbed,
      hasLocalizedPage: hasLocalizedPage,
      services: services,
      content: htmlContent.substring(0, 5000), // First 5000 chars for analysis
      note: 'Website analysis completed'
    };
    
  } catch (error) {
    console.error('❌ Website analysis error:', error.message);
    return {
      hasGBPEmbed: false,
      hasLocalizedPage: false,
      services: [],
      content: '',
      note: `Website analysis failed: ${error.message}`
    };
  }
}

// 7. Q&A ANALYSIS - Enhanced Q&A detection using ScrapingBee
async function analyzeQAWithScraping(businessName, location, placeId) {
  try {
    console.log(`❓ Analyzing Q&A with ScrapingBee: ${businessName}`);
    
    if (!SCRAPINGBEE_API_KEY) {
      console.log('⚠️ ScrapingBee API key not configured, falling back to SerpAPI');
      return await analyzeQuestionsAndAnswers(businessName, location, placeId);
    }
    
    // Construct Google Maps URL for the business
    let mapsUrl;
    if (placeId) {
      // Use place_id if available for more accurate results
      mapsUrl = `https://www.google.com/maps/place/?q=place_id:${placeId}`;
    } else {
      // Fallback to search-based URL
      const { city, state, isCounty } = extractCityState(location);
      const searchQuery = isCounty ? `${businessName} ${city} County ${state}` : `${businessName} ${location}`;
      mapsUrl = `https://www.google.com/maps/search/${encodeURIComponent(searchQuery)}`;
    }
    
    console.log(`📍 Using Maps URL: ${mapsUrl.substring(0, 100)}...`);
    
    // Use ScrapingBee to get the Maps page HTML
    const response = await axios.get('https://app.scrapingbee.com/api/v1', {
      params: {
        api_key: SCRAPINGBEE_API_KEY,
        url: mapsUrl,
        custom_google: 'true',
        premium_proxy: 'true', // Required for Google Maps
        render_js: 'true',
        wait: '5000', // Wait for Q&A section to load
        window_width: '1920',
        window_height: '1080'
      },
      timeout: 45000  // Reduced from 60s to 45s // Give it more time due to premium proxy
    });
    
    const html = response.data;
    console.log(`📄 Retrieved HTML (${html.length} characters)`);
    
    // Check for Q&A indicators
    const qaIndicators = [
      'Questions & answers',
      'Questions and answers',
      'Ask a question',
      'Be the first to ask a question',
      'questions have been asked',
      'Most relevant questions'
    ];
    
    let hasQA = false;
    let qaIndicatorFound = '';
    
    for (const indicator of qaIndicators) {
      if (html.includes(indicator)) {
        hasQA = true;
        qaIndicatorFound = indicator;
        console.log(`✅ Found Q&A indicator: "${indicator}"`);
        break;
      }
    }
    
    if (!hasQA) {
      console.log('❌ No Q&A section found');
      return {
        hasQA: false,
        questionCount: 0,
        questions: [],
        note: 'No Q&A section detected on Google Maps page'
      };
    }
    
    // Extract questions from aria-labels
    const questionPattern = /aria-label="([^"]+\?[^"]*)"/g;
    const questions = [];
    let match;
    
    while ((match = questionPattern.exec(html)) !== null) {
      const question = match[1].trim();
      // Validate it's actually a question
      if (question.length > 10 && question.includes('?')) {
        questions.push(question);
      }
    }
    
    // Also look for questions in other patterns
    const altQuestionPattern = /<span[^>]*>([^<]+\?[^<]*)<\/span>/g;
    while ((match = altQuestionPattern.exec(html)) !== null) {
      const question = match[1].trim();
      if (question.length > 10 && question.includes('?') && !questions.includes(question)) {
        questions.push(question);
      }
    }
    
    // Check if Q&A section exists but is empty
    if (hasQA && questions.length === 0) {
      if (html.includes('Be the first to ask a question')) {
        console.log('📝 Q&A section exists but no questions have been asked yet');
        return {
          hasQA: true,
          questionCount: 0,
          questions: [],
          note: 'Q&A section exists but no questions have been asked yet'
        };
      }
    }
    
    console.log(`✅ Found ${questions.length} questions in Q&A section`);
    if (questions.length > 0) {
      console.log('🔍 Sample questions:', questions.slice(0, 2));
    }
    
    return {
      hasQA: true,
      questionCount: questions.length,
      questions: questions.slice(0, 5), // Store first 5 for reference
      note: questions.length > 0 
        ? `Found ${questions.length} questions and answers`
        : 'Q&A section exists but no questions detected'
    };
    
  } catch (error) {
    console.error('❌ ScrapingBee Q&A analysis error:', error.message);
    console.log('🔄 Falling back to SerpAPI Q&A analysis');
    
    // Fallback to the original SerpAPI method
    try {
      return await analyzeQuestionsAndAnswers(businessName, location, placeId);
    } catch (fallbackError) {
      console.error('❌ Fallback Q&A analysis also failed:', fallbackError.message);
      return { 
        hasQA: false,
        questionCount: 0,
        questions: [],
        note: `Q&A analysis failed: ${error.message}`
      };
    }
  }
}

// 7. Q&A ANALYSIS (LEGACY) - Get Q&A data directly from SerpAPI
async function analyzeQuestionsAndAnswers(businessName, location, placeId) {
  try {
    console.log(`❓ Analyzing Q&A for: ${businessName}`);
    
    if (!SERPAPI_KEY) {
      throw new Error('SerpAPI key not configured');
    }
    
    // First get place_id if we don't have a reliable one
    let businessPlaceId = placeId;
    console.log(`🔍 Q&A Analysis starting with place_id: ${businessPlaceId || 'NOT PROVIDED'}`);
    
    if (!businessPlaceId) {
      console.log('🔍 Getting place_id for Q&A analysis...');
      
      // Detect location for better search results
      const { region } = detectCountryRegion(location);
      const googleDomain = region === 'AE' ? 'google.ae' : region === 'GB' ? 'google.co.uk' : 'google.com';
      
      const searchResponse = await axios.get('https://serpapi.com/search.json', {
        params: {
          engine: 'google_local',
          q: `${businessName} ${location}`,
          api_key: SERPAPI_KEY,
          google_domain: googleDomain,
          gl: region.toLowerCase(),
          hl: 'en'
        },
        timeout: 10000  // Reduced timeout for faster failures
      });
      
      if (searchResponse.data.local_results && searchResponse.data.local_results.length > 0) {
        const business = searchResponse.data.local_results[0];
        businessPlaceId = business.place_id;
        console.log(`✅ Found place_id for Q&A: ${businessPlaceId}`);
      }
    }
    
    if (!businessPlaceId) {
      return { 
        hasQA: false,
        questionCount: 0,
        questions: [],
        note: 'Could not find place_id for Q&A analysis'
      };
    }
    
    // Get Q&A data using Google Maps Place Results API
    console.log('❓ Getting Q&A data from Google Maps...');
    
    const qaResponse = await axios.get('https://serpapi.com/search.json', {
      params: {
        engine: 'google_maps',
        type: 'place',
        place_id: businessPlaceId,
        api_key: SERPAPI_KEY
      },
      timeout: 15000
    });
    
    console.log('📊 Q&A Response received');
    console.log('🔍 DEBUG - QA Response structure:', {
      hasPlaceResult: !!qaResponse.data.place_result,
      placeResultKeys: qaResponse.data.place_result ? Object.keys(qaResponse.data.place_result) : [],
      hasQuestionsAndAnswers: !!qaResponse.data.place_result?.questions_and_answers,
      qaLength: qaResponse.data.place_result?.questions_and_answers?.length || 0
    });
    
    // Extract Q&A data from response
    const placeResults = qaResponse.data.place_result;
    const questionsAndAnswers = placeResults?.questions_and_answers || [];
    
    if (questionsAndAnswers.length > 0) {
      console.log(`✅ Found ${questionsAndAnswers.length} Q&A items`);
      console.log('🔍 Sample Q&A:', questionsAndAnswers.slice(0, 2));
      
      return {
        hasQA: true,
        questionCount: questionsAndAnswers.length,
        questions: questionsAndAnswers.slice(0, 5), // Store first 5 for reference
        note: `Found ${questionsAndAnswers.length} questions and answers`
      };
    } else {
      console.log('❌ No Q&A found in response');
      console.log('🔍 Full response structure:', JSON.stringify(qaResponse.data, null, 2));
      return {
        hasQA: false,
        questionCount: 0,
        questions: [],
        note: 'No questions and answers found in API response'
      };
    }
    
  } catch (error) {
    console.error('❌ Q&A analysis error:', error.message);
    return { 
      hasQA: false,
      questionCount: 0,
      questions: [],
      note: `Q&A analysis failed: ${error.message}`
    };
  }
}

// 8. SERVICES EXTRACTION - Get service types from SerpAPI Google Maps
async function getBusinessServices(businessName, location, placeId) {
  try {
    console.log(`🔧 Getting services for: ${businessName}`);

    if (!SERPAPI_KEY) {
      throw new Error('SerpAPI key not configured');
    }

    // Use place_id if available for direct lookup
    let queryParams;

    if (placeId) {
      console.log(`🎯 Using place_id for service lookup: ${placeId}`);
      queryParams = {
        engine: 'google_maps',
        type: 'place',
        place_id: placeId,
        api_key: SERPAPI_KEY,
        hl: 'en'
      };
    } else {
      // Fall back to search if no place_id
      console.log(`🔍 Searching for business to get services`);
      queryParams = {
        engine: 'google_maps',
        type: 'search',
        q: `${businessName} ${location}`,
        api_key: SERPAPI_KEY,
        hl: 'en'
      };
    }

    const response = await axios.get('https://serpapi.com/search.json', {
      params: queryParams,
      timeout: 15000
    });

    // Check for API errors first
    if (response.data.error) {
      console.log(`⚠️ SerpAPI error: ${response.data.error}`);
      console.log('🔄 Falling back to empty services (API limitation)');
      return {
        hasServices: false,
        serviceCount: 0,
        services: [],
        serviceOptions: {},
        note: `SerpAPI error: ${response.data.error}`
      };
    }

    // Extract services from the type field in place_results
    const placeResults = response.data.place_results;

    if (placeResults && placeResults.type) {
      const services = Array.isArray(placeResults.type) ? placeResults.type : [placeResults.type];

      console.log(`✅ Found ${services.length} services: ${services.join(', ')}`);

      return {
        hasServices: services.length > 0,
        serviceCount: services.length,
        services: services,
        serviceOptions: placeResults.service_options || {},
        note: `Found ${services.length} service types`
      };
    } else {
      console.log('❌ No services found in SerpAPI response');
      return {
        hasServices: false,
        serviceCount: 0,
        services: [],
        serviceOptions: {},
        note: 'No service types found in API response'
      };
    }

  } catch (error) {
    console.error('❌ Service extraction error:', error.message);
    return {
      hasServices: false,
      serviceCount: 0,
      services: [],
      serviceOptions: {},
      note: `Service extraction failed: ${error.message}`
    };
  }
}

// Helper function to extract city and state/country from location string
function extractCityState(location) {
  // Handle full address format (e.g., "123 Main St, Miami, FL 33101")
  const parts = location.split(/[,\-]/).map(p => p.trim()).filter(p => p.length > 0);
  
  // County/state detection patterns
  const countyPatterns = [
    /(.+)\s+county\s*,\s*([A-Z]{2})$/i,     // "Salt Lake County, UT"
    /(.+)\s+county\s*,\s*([A-Za-z\s]+)$/i,  // "Salt Lake County, Utah"
    /(.+)\s+co\.\s*,\s*([A-Z]{2})$/i,       // "Utah Co., UT"
    /(.+)\s+co\s*,\s*([A-Z]{2})$/i          // "Utah Co, UT"
  ];
  
  // Check for county, state patterns first
  const locationString = location.trim();
  for (const pattern of countyPatterns) {
    const match = locationString.match(pattern);
    if (match) {
      console.log(`🗺️ Detected county format: ${match[1]} County, ${match[2]}`);
      return {
        city: match[1], // Use county name as the primary location identifier
        state: match[2],
        isCounty: true  // Flag to indicate this is a county-level location
      };
    }
  }
  
  // For international addresses, the format might be different
  // e.g., "Al Sufouh - Dubai - United Arab Emirates"
  
  if (parts.length === 2) {
    // Simple "City, ST" or "City, Country" format
    return {
      city: parts[0],
      state: parts[1]
    };
  } else if (parts.length >= 3) {
    // Complex format - try to identify city and state/country
    const lastPart = parts[parts.length - 1].trim();
    const secondLastPart = parts[parts.length - 2].trim();
    
    // Check if last part is a country name
    const countryNames = ['united arab emirates', 'uae', 'united kingdom', 'uk', 'usa', 'united states', 'canada', 'australia', 'germany', 'france', 'spain', 'italy'];
    if (countryNames.some(country => lastPart.toLowerCase().includes(country))) {
      // Last part is country, second last is likely city or state
      return {
        city: secondLastPart,
        state: lastPart
      };
    }
    
    // Check if last part is a zip code
    if (/^\d{5}(-\d{4})?$/.test(lastPart)) {
      // Extract state from second last part (e.g., "FL 33101" -> "FL")
      const stateMatch = secondLastPart.match(/^([A-Z]{2})\s+\d{5}/i) || secondLastPart.match(/^([A-Z]{2})$/i);
      if (stateMatch) {
        return {
          city: parts[parts.length - 3] || secondLastPart.replace(/\s*[A-Z]{2}\s*\d{5}.*$/i, '').trim(),
          state: stateMatch[1].toUpperCase()
        };
      }
    } else if (/^[A-Z]{2}$/i.test(lastPart)) {
      // Last part is state abbreviation
      return {
        city: secondLastPart,
        state: lastPart.toUpperCase()
      };
    }
    
    // For addresses with many parts, try to identify known city names
    const knownCities = ['dubai', 'abu dhabi', 'sharjah', 'london', 'paris', 'sydney', 'toronto', 'singapore'];
    for (let i = parts.length - 1; i >= 0; i--) {
      if (knownCities.some(city => parts[i].toLowerCase().includes(city))) {
        return {
          city: parts[i],
          state: parts[parts.length - 1] // Use last part as state/country
        };
      }
    }
  }
  
  // Fallback - use the most significant parts
  if (parts.length >= 2) {
    // Try to find the most likely city (usually one of the middle parts)
    const middleIndex = Math.floor(parts.length / 2);
    return {
      city: parts[middleIndex] || parts[0],
      state: parts[parts.length - 1] || ''
    };
  }
  
  return {
    city: parts[0] || location,
    state: ''
  };
}

// Helper function to extract services from HTML
function extractServicesFromHTML(htmlContent) {
  try {
    const services = [];
    const htmlLower = htmlContent.toLowerCase();
    
    // Look for service-related sections
    const servicePatterns = [
      /services?[^<]*:([^<]+)/gi,
      /we offer[^<]*:([^<]+)/gi,
      /our services include[^<]*:([^<]+)/gi,
      /<h[1-6][^>]*>([^<]*(?:service|solution|product)[^<]*)<\/h[1-6]>/gi,
      /<li[^>]*>([^<]*(?:service|solution|consulting|management|design|development)[^<]*)<\/li>/gi
    ];
    
    servicePatterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(htmlContent)) !== null && services.length < 10) {
        const service = match[1].trim().replace(/[^\w\s-]/g, '');
        if (service.length > 5 && service.length < 100) {
          services.push(service);
        }
      }
    });
    
    // Remove duplicates and return top 6
    return [...new Set(services)].slice(0, 6);
    
  } catch (error) {
    console.error('❌ Service extraction error:', error.message);
    return [];
  }
}
// 6. REVIEWS ANALYSIS - Check for recent reviews and business responses
async function analyzeReviews(businessName, location, placeId) {
  try {
    console.log(`📝 Analyzing reviews for: ${businessName}`);
    
    if (!SERPAPI_KEY) {
      throw new Error('SerpAPI key not configured');
    }
    
    // First get place info if we don't have a reliable place_id
    let businessPlaceId = placeId;
    
    if (!businessPlaceId) {
      console.log('🔍 Getting place info from SerpAPI...');
      
      // Detect location for better search results
      const { region } = detectCountryRegion(location);
      const googleDomain = region === 'AE' ? 'google.ae' : region === 'GB' ? 'google.co.uk' : 'google.com';
      
      const searchResponse = await axios.get('https://serpapi.com/search.json', {
        params: {
          engine: 'google_local',
          q: `${businessName} ${location}`,
          api_key: SERPAPI_KEY,
          google_domain: googleDomain,
          gl: region.toLowerCase(),
          hl: 'en'
        },
        timeout: 10000  // Reduced timeout for faster failures
      });
      
      if (searchResponse.data.local_results && searchResponse.data.local_results.length > 0) {
        const business = searchResponse.data.local_results[0];
        businessPlaceId = business.place_id;
        console.log(`✅ Found place_id: ${businessPlaceId}`);
      }
    }
    
    if (!businessPlaceId) {
      return { 
        hasRecentReview: false,
        hasBusinessResponses: false,
        note: 'Could not find place_id for detailed review analysis'
      };
    }
    
    // Get detailed reviews using place_id
    console.log('🔍 Getting detailed reviews...');
    
    const reviewsResponse = await axios.get('https://serpapi.com/search.json', {
      params: {
        engine: 'google_maps_reviews',
        place_id: businessPlaceId,
        api_key: SERPAPI_KEY
      },
      timeout: 15000
    });
    
    if (reviewsResponse.data.error) {
      return { 
        hasRecentReview: false,
        hasBusinessResponses: false,
        note: `Reviews not available: ${reviewsResponse.data.error}`
      };
    }
    
    if (reviewsResponse.data.reviews && reviewsResponse.data.reviews.length > 0) {
      const reviews = reviewsResponse.data.reviews;
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      
      // Check for recent reviews
      const hasRecentReview = reviews.some(review => {
        if (!review.iso_date) return false;
        const reviewDate = new Date(review.iso_date);
        return reviewDate > thirtyDaysAgo;
      });
      
      // Check for business responses
      const hasBusinessResponses = reviews.some(review => 
        review.response && review.response.snippet && review.response.snippet.trim().length > 0
      );
      
      console.log(`✅ Reviews analysis: ${reviews.length} total, recent: ${hasRecentReview}, responses: ${hasBusinessResponses}`);
      
      return { 
        hasRecentReview: hasRecentReview,
        hasBusinessResponses: hasBusinessResponses,
        reviewCount: reviews.length,
        note: 'Review analysis completed'
      };
    }
    
    return { 
      hasRecentReview: false,
      hasBusinessResponses: false,
      reviewCount: 0,
      note: 'No detailed reviews available'
    };
    
  } catch (error) {
    console.error('❌ Reviews analysis error:', error.message);
    return { 
      hasRecentReview: false,
      hasBusinessResponses: false,
      reviewCount: 0,
      note: `Reviews analysis failed: ${error.message}`
    };
  }
}

// 7. COMPLETE SCORING SYSTEM (UPDATED V3)
async function calculateScore(data) {
  console.log(`📊 Calculating score for: ${data.businessInfo.businessName}`);
  console.log('🔍 SCORING DEBUG - Raw Data:');
  console.log(`   Photos: ${data.outscraper.photos_count}`);
  console.log(`   Categories: ${data.outscraper.categories.length} (${data.outscraper.categories.join(', ')})`);
  console.log(`   Reviews: ${data.outscraper.reviews}, Rating: ${data.outscraper.rating}`);
  console.log(`   Verified: ${data.outscraper.verified}`);
  console.log(`   Description length: ${data.outscraper.description?.length || 0}`);
  
  const scores = {
    claimed: 0,           // 4 pts (reduced from 8)
    description: 0,       // 10 pts
    categories: 0,        // 8 pts
    productTiles: 0,      // 10 pts
    photos: 0,            // 8 pts
    posts: 0,             // 6 pts (reduced from 8)
    social: 0,            // 2 pts
    reviews: 0,           // 12 pts (3 each for 4 criteria)
    citations: 0,         // 10 pts (1 per directory)
    gbpEmbed: 0,          // 8 pts
    landingPage: 0,       // 8 pts
    hours: 0,             // 4 pts - NEW
    address: 0,           // 4 pts - NEW
    keywordInName: 0,     // 4 pts - NEW
    services: 0           // 4 pts - NEW
    // Q&A removed (was 4 pts) - no longer available on GBPs
    // Total: 102 pts
  };
  
  const details = {};
  
  // 1. CLAIMED PROFILE (4 pts) - Binary
  if (data.outscraper.verified || data.outscraper.rating > 0) {
    scores.claimed = 4;
    details.claimed = { status: 'GOOD', message: 'Profile verified - you have full control' };
  } else {
    scores.claimed = 0;
    details.claimed = { status: 'MISSING', message: 'Profile unclaimed - can\'t manage your listing' };
  }
  
  // 2. BUSINESS DESCRIPTION (10 pts) - 0/5/10 based on criteria
  // Check Outscraper first, fallback to AI analysis if Outscraper doesn't have description
  const desc = data.outscraper.description;
  const hasDescriptionFromAI = data.aiAnalysis?.description?.exists || false;
  const descriptionLengthFromAI = data.aiAnalysis?.description?.estimatedLength || 0;

  console.log(`🔍 DESCRIPTION DEBUG: Outscraper="${desc?.substring(0, 50) || 'EMPTY'}", AI.exists=${hasDescriptionFromAI}, AI.length=${descriptionLengthFromAI}`);

  // If Outscraper has description, analyze it fully
  if (desc && desc.length > 0) {
    const descAnalysis = analyzeDescriptionCriteria(desc, data.businessInfo.businessName, data.businessInfo.location, data.businessInfo.industry);

    if (descAnalysis.criteriaCount === 3) {
      scores.description = 10;
      details.description = { status: 'GOOD', message: 'Great description that helps customers find you' };
    } else {
      scores.description = 5;
      details.description = { status: 'NEEDS IMPROVEMENT', message: 'Basic description detected - could be more compelling' };
    }
  }
  // If Outscraper missing but AI detected description from screenshot
  else if (hasDescriptionFromAI) {
    // Give partial credit based on length estimate from AI
    if (descriptionLengthFromAI >= 150) {
      scores.description = 5;
      details.description = { status: 'NEEDS IMPROVEMENT', message: 'Description detected (estimated 150+ chars) - good start' };
    } else if (descriptionLengthFromAI > 0) {
      scores.description = 3;
      details.description = { status: 'NEEDS IMPROVEMENT', message: 'Short description detected - could be more detailed' };
    } else {
      scores.description = 2;
      details.description = { status: 'NEEDS IMPROVEMENT', message: 'Description present but quality unknown' };
    }
  }
  // No description found anywhere
  else {
    scores.description = 0;
    details.description = { status: 'MISSING', message: 'No description found - missing opportunity to tell your story' };
  }
  
  // 3. CATEGORIES (8 pts) - 0 if only primary, 5 if 2-3 total, 8 if 4+ total
  const totalCategories = data.outscraper.categories.length;
  if (totalCategories >= 4) {
    scores.categories = 8;
    details.categories = { status: 'GOOD', message: 'Well categorized - easier for customers to find you' };
  } else if (totalCategories >= 2) {
    scores.categories = 5;
    details.categories = { status: 'NEEDS IMPROVEMENT', message: 'Limited categories - missing search opportunities' };
  } else {
    scores.categories = 0;
    details.categories = { status: 'MISSING', message: 'Only one category - limiting your visibility' };
  }
  
  // 4. PRODUCT TILES (10 pts) - Binary
  if (data.aiAnalysis.productTiles && data.aiAnalysis.productTiles.hasAny) {
    scores.productTiles = 10;
    details.productTiles = { status: 'GOOD', message: 'Services/products showcased effectively' };
  } else {
    scores.productTiles = 0;
    details.productTiles = { status: 'MISSING', message: 'No services shown - customers can\'t see what you offer' };
  }
  
  // 5. PHOTOS (8 pts) - 0 if none, 4 if <10, 8 if 10+
  const photoCount = data.outscraper.photos_count;
  if (photoCount >= 10) {
    scores.photos = 8;
    details.photos = { status: 'GOOD', message: 'Strong visual presence helps attract customers' };
  } else if (photoCount > 0) {
    scores.photos = 4;
    details.photos = { status: 'NEEDS IMPROVEMENT', message: 'Limited photos - customers want to see more' };
  } else {
    scores.photos = 0;
    details.photos = { status: 'MISSING', message: 'No photos - businesses with photos get 42% more requests' };
  }
  
  // 6. POSTS (6 pts) - Binary: recent activity
  if (data.aiAnalysis.posts && data.aiAnalysis.posts.hasRecent) {
    scores.posts = 6;
    details.posts = { status: 'GOOD', message: 'Active posting keeps customers engaged' };
  } else {
    scores.posts = 0;
    details.posts = { status: 'MISSING', message: 'No recent posts - missing chance to engage customers' };
  }
  
  // 7. Q&A REMOVED - Google removed this feature from Business Profiles
  // Commenting out for historical reference but no longer scoring

  // 8. SOCIAL PROFILES (2 pts) - Binary (was #8, now #7 after Q&A removal)
  console.log(`🔍 SOCIAL DEBUG: social.hasAny=${data.aiAnalysis.social?.hasAny}, count=${data.aiAnalysis.social?.count}, socialLinks.meets2Plus=${data.aiAnalysis.socialLinks?.meets2Plus}`);

  if (data.aiAnalysis.social && data.aiAnalysis.social.hasAny) {
    scores.social = 2;
    details.social = { status: 'GOOD', message: 'Social media links help customers connect' };
  } else {
    scores.social = 0;
    details.social = { status: 'MISSING', message: 'No social links - missing connection opportunities' };
  }
  
  // 9. REVIEWS (12 pts) - 3 pts each for 4 criteria - ADD DEBUG LOGGING
  let reviewScore = 0;
  const reviewCriteria = [];
  
  console.log(`🔍 REVIEW DEBUG: Reviews: ${data.outscraper.reviews}, Rating: ${data.outscraper.rating}`);
  console.log(`🔍 REVIEW DEBUG: Recent review: ${data.reviewsAnalysis?.hasRecentReview}, Business responses: ${data.reviewsAnalysis?.hasBusinessResponses}`);
  
  if (data.outscraper.reviews >= 10) {
    reviewScore += 3;
    reviewCriteria.push('10+ reviews');
  }
  if (data.outscraper.rating >= 4.4) {
    reviewScore += 3;
    reviewCriteria.push('4.4+ rating');
  }
  if (data.reviewsAnalysis && data.reviewsAnalysis.hasRecentReview) {
    reviewScore += 3;
    reviewCriteria.push('recent review');
  }
  if (data.reviewsAnalysis && data.reviewsAnalysis.hasBusinessResponses) {
    reviewScore += 3;
    reviewCriteria.push('business responses');
  }
  
  console.log(`🔍 REVIEW DEBUG: Final review score: ${reviewScore}/12, Criteria met: ${reviewCriteria.join(', ')}`);
  
  scores.reviews = reviewScore;
  details.reviews = { 
    status: reviewScore >= 9 ? 'GOOD' : (reviewScore >= 6 ? 'NEEDS IMPROVEMENT' : 'MISSING'),
    message: reviewScore >= 9 ? 'Strong review presence builds trust' : (reviewScore >= 6 ? 'Good start - keep encouraging reviews' : 'Limited reviews - affecting customer trust')
  };
  
  // 10. CITATIONS (10 pts) - 1 pt per directory found
  scores.citations = data.citations.stats.score;
  if (scores.citations >= 8) {
    details.citations = { status: 'GOOD', message: 'Excellent online presence across directories' };
  } else if (scores.citations >= 5) {
    details.citations = { status: 'NEEDS IMPROVEMENT', message: 'Found in some directories - expand your reach' };
  } else {
    details.citations = { status: 'MISSING', message: 'Limited directory presence hurts local rankings' };
  }
  
  // 11. GBP EMBED (8 pts) - Binary
  if (data.websiteAnalysis.hasGBPEmbed) {
    scores.gbpEmbed = 8;
    details.gbpEmbed = { status: 'GOOD', message: 'Map on website helps customers find you' };
  } else {
    scores.gbpEmbed = 0;
    details.gbpEmbed = { status: 'MISSING', message: 'No map on website - harder for customers to visit' };
  }
  
  // 12. LOCAL LANDING PAGE (8 pts) - Binary
  if (data.websiteAnalysis.hasLocalizedPage) {
    scores.landingPage = 8;
    details.landingPage = { status: 'GOOD', message: 'Local page targets your community effectively' };
  } else {
    scores.landingPage = 0;
    details.landingPage = { status: 'MISSING', message: 'No local page - missing local search traffic' };
  }

  // 13. HOURS OF OPERATION (4 pts) - Binary: Are hours displayed?
  const hasHours = data.outscraper.hours && Object.keys(data.outscraper.hours).length > 0;
  if (hasHours) {
    scores.hours = 4;
    details.hours = {
      status: 'GOOD',
      message: 'Hours of operation is a real ranking factor for your business, and if you are closed during the time of a search, you will rank lower. If possible, expand your hours of operation to ensure the highest ranking at all times'
    };
  } else {
    scores.hours = 0;
    details.hours = {
      status: 'MISSING',
      message: 'No hours listed - add your hours of operation to improve rankings. If you are closed during the time of a search, you will rank lower'
    };
  }

  // 14. ADDRESS VISIBILITY (4 pts) - Binary: Public address vs Service Area Business
  const hasVisibleAddress = Boolean(
    data.outscraper.address &&
    !data.outscraper.is_service_area_business &&
    data.outscraper.address !== 'Service area business'
  );

  if (hasVisibleAddress) {
    scores.address = 4;
    details.address = {
      status: 'GOOD',
      message: 'Visible public address helps with local rankings'
    };
  } else {
    scores.address = 0;
    details.address = {
      status: 'MISSING',
      message: 'A public address is a ranking factor, but only if there is a real physical location. Service area businesses have reduced map visibility'
    };
  }

  // 15. KEYWORD IN BUSINESS NAME (4 pts) - Analyzed with AI
  let keywordAnalysis = null;
  try {
    keywordAnalysis = await analyzeBusinessNameKeywords(
      data.businessInfo.businessName,
      data.businessInfo.industry
    );
  } catch (error) {
    console.error('⚠️ Keyword analysis failed:', error.message);
    keywordAnalysis = { hasKeywords: false, matchedKeywords: [], missingKeywords: [] };
  }

  if (keywordAnalysis && keywordAnalysis.hasKeywords) {
    scores.keywordInName = 4;
    details.keywordInName = {
      status: 'GOOD',
      message: `Business name includes relevant keywords (${keywordAnalysis.matchedKeywords.join(', ')}) - excellent for rankings`
    };
  } else {
    scores.keywordInName = 0;
    details.keywordInName = {
      status: 'MISSING',
      message: 'No industry keywords in business name - Google has rules for this, but when possible, we suggest adding a relevant keyword to the business name, which does impact ranking'
    };
  }

  // 16. SERVICES SECTION (4 pts) - From Services tab screenshot analysis
  const servicesData = data.servicesAnalysis || {};
  const servicesCount = servicesData.servicesCount || 0;
  const hasDescriptions = servicesData.hasDescriptions || false;

  if (servicesCount >= 3 && hasDescriptions) {
    scores.services = 4;
    details.services = {
      status: 'GOOD',
      message: `${servicesCount} services listed with descriptions - great for capturing keyword variations`
    };
  } else if (servicesCount > 0 && servicesCount < 3) {
    scores.services = 2;
    details.services = {
      status: 'NEEDS IMPROVEMENT',
      message: `Only ${servicesCount} service${servicesCount === 1 ? '' : 's'} listed - add at least 3 services with detailed descriptions`
    };
  } else if (servicesCount >= 3 && !hasDescriptions) {
    scores.services = 2;
    details.services = {
      status: 'NEEDS IMPROVEMENT',
      message: `${servicesCount} services listed but missing descriptions - add detailed descriptions to each service`
    };
  } else {
    scores.services = 0;
    details.services = {
      status: 'MISSING',
      message: 'No Services section found - add 5+ services with detailed descriptions to improve rankings'
    };
  }

  // Calculate base score
  let totalScore = Object.values(scores).reduce((sum, score) => sum + score, 0);
  
  // BONUS POINTS: 1 point per 2 GREEN/GOOD factors
  const goodFactors = Object.entries(details).filter(([key, detail]) => 
    detail.status === 'GOOD'
  ).length;
  const bonusPoints = Math.floor(goodFactors / 2);
  
  console.log(`🌟 BONUS: ${goodFactors} good factors = ${bonusPoints} bonus points`);
  totalScore += bonusPoints;
  
  // Store bonus info for display
  scores.bonus = bonusPoints;
  details.bonus = { 
    status: 'BONUS', 
    message: `${bonusPoints} bonus points earned (${goodFactors} green factors)` 
  };
  
  // Calculate actual max score
  // Max score is now 96 (was 100 before Q&A removal: 100 - 4 = 96)
  // For fast bulk audits: Citations (10), GBP Embed (8) = -18 points (Landing Page IS included)
  const isFastBulkAudit = !data.citations || data.citations.stats.score === 0;
  const actualMaxScore = isFastBulkAudit ? 78 : 96; // 96 for full audits, 78 for fast bulk (96 - 10 citations - 8 gbp embed = 78)

  console.log(`📊 Final Score: ${totalScore}/${actualMaxScore}`);

  return {
    totalScore: totalScore,
    maxScore: actualMaxScore,
    scores: scores,
    details: details,
    isFastBulkAudit: isFastBulkAudit
  };
}
// Helper function to analyze description criteria
function analyzeDescriptionCriteria(description, businessName, location, industry) {
  if (!description) {
    return { criteriaCount: 0, hasLocalKeywords: false, hasServices: false, hasCTA: false };
  }
  
  const descLower = description.toLowerCase();
  const { city } = extractCityState(location);
  const cityLowerCase = city.toLowerCase();
  
  // Check for localized keywords (expanded patterns)
  const localPatterns = [
    `${cityLowerCase}`,
    `local`,
    `serving ${cityLowerCase}`,
    `${cityLowerCase} area`,
    `${cityLowerCase} ${industry.toLowerCase()}`,
    `${industry.toLowerCase()} in ${cityLowerCase}`,
    `based in ${cityLowerCase}`,
    `located in ${cityLowerCase}`,
    `${cityLowerCase} based`,
    `near ${cityLowerCase}`,
    `around ${cityLowerCase}`,
    `throughout ${cityLowerCase}`,
    `community`,
    `neighborhood`,
    `locally owned`,
    `family owned`,
    `established`,
    `trusted`,
    `reliable`
  ];
  const hasLocalKeywords = localPatterns.some(pattern => descLower.includes(pattern));
  
  // Check for services overview (expanded patterns)
  const servicePatterns = [
    'we provide', 'we offer', 'our services', 'services include',
    'we specialize', 'expertise in', 'professional', 'expert',
    'specializing in', 'offering', 'providing', 'delivering',
    'solutions', 'helping', 'committed to', 'dedicated to',
    'focused on', 'skilled in', 'experienced in', 'trained',
    'certified', 'licensed', 'qualified', 'team of',
    'years of experience', 'comprehensive', 'full service',
    'custom', 'tailored', 'personalized'
  ];
  const hasServices = servicePatterns.some(pattern => descLower.includes(pattern));
  
  // Check for call to action (expanded patterns)
  const ctaPatterns = [
    'contact us', 'call us', 'reach out', 'schedule', 'book',
    'get started', 'learn more', 'visit us', 'today',
    'call today', 'call now', 'phone', 'email us',
    'request', 'inquire', 'ask about', 'speak with',
    'discuss', 'consultation', 'estimate', 'quote',
    'appointment', 'meeting', 'available', 'ready to help',
    'here to help', 'let us', 'we can help', 'talk to us',
    'reach us', 'message us', 'questions', 'interested',
    'more information', 'details', 'find out more'
  ];
  const hasCTA = ctaPatterns.some(pattern => descLower.includes(pattern));
  
  const criteriaCount = [hasLocalKeywords, hasServices, hasCTA].filter(Boolean).length;
  
  return { criteriaCount, hasLocalKeywords, hasServices, hasCTA };
}

// 8. SMART SUGGESTION GENERATION
async function generateSmartSuggestions(businessInfo, scoreData, websiteServices) {
  try {
    console.log(`🧠 Generating smart suggestions for: ${businessInfo.businessName}`);
    
    if (!OPENAI_API_KEY) {
      throw new Error('OpenAI API key not configured for smart suggestions');
    }
    
    const suggestions = {};
    const { businessName, location, industry, website } = businessInfo;
    const { city, state } = extractCityState(location);
    
    // 1. Business Description (if needed)
    if (scoreData.scores.description < 10) {
      const descriptionPrompt = `
      Generate an SEO-optimized Google Business Profile description for:
      Business: ${businessName}
      Industry: ${industry}
      Location: ${city}, ${state}
      Website Services Found: ${websiteServices.join(', ') || 'None detected'}
      
      Requirements:
      - 400+ characters
      - Include local keywords (${city}, ${industry})
      - Mention specific services
      - Include a call-to-action
      - Professional but approachable tone
      
      Return only the description text, no quotes or formatting.
      `;
      
      suggestions.businessDescription = await callOpenAI(descriptionPrompt, 'description');
    }
    
    // 2. Category Suggestions (if needed)
    if (scoreData.scores.categories < 8) {
      const categoryPrompt = `
      CRITICAL: You MUST only suggest categories that exist in Google's official Business Profile category list (approximately 4,000+ real categories).
      DO NOT invent or create categories. ONLY use exact category names from Google's actual category database.

      Suggest Google Business Profile categories for:
      Business: ${businessName}
      Industry: ${industry}
      Services: ${websiteServices.join(', ') || 'General services'}

      Requirements:
      - Provide 6-8 categories that ACTUALLY EXIST in Google Business Profile
      - Include one primary category (most specific match) and 5-7 secondary categories
      - Use exact category names as they appear in Google Business Profile (check your knowledge of the real category list)
      - Return as a simple list, one per line, no numbering
      - Verify each category exists before suggesting it
      - Do NOT make up creative category names - they must be real Google categories

      Example real categories: "Restaurant", "Italian restaurant", "Pizza restaurant", "Hair salon", "Plumber", "Auto repair shop"
      `;

      suggestions.categories = await callOpenAI(categoryPrompt, 'categories');
    }
    
    // 3. Product Tiles (if needed)
    if (scoreData.scores.productTiles < 10) {
      const tilesPrompt = `
      Create 4-6 product/service tiles for Google Business Profile:
      Business: ${businessName}
      Industry: ${industry}
      Website Services: ${websiteServices.join(', ') || 'General services'}
      
      For each tile, provide:
      - Service name (keyword-rich, 2-4 words)
      - Description (1-2 sentences, under 100 characters)
      
      Format as:
      Service Name
      Description text here
      
      (blank line between each)
      `;
      
      suggestions.productTiles = await callOpenAI(tilesPrompt, 'product tiles');
    }
    
    // 4. Post Ideas (if needed)
    if (scoreData.scores.posts < 8) {
      const postsPrompt = `
      Create 5 Google Business Post ideas for:
      Business: ${businessName}
      Industry: ${industry}
      Location: ${city}, ${state}
      
      Each post should be:
      - 150-200 characters
      - Include local keywords
      - Have a call-to-action
      - Be engaging and professional
      
      Format as numbered list (1-5).
      `;
      
      suggestions.posts = await callOpenAI(postsPrompt, 'posts');
    }
    
    // 5. Q&A Content (if needed)
    if (scoreData.scores.qa < 4) {
      const qaPrompt = `
      Create 5 Q&A pairs for Google Business Profile:
      Business: ${businessName}
      Industry: ${industry}
      Location: ${city}, ${state}
      
      Questions should be common customer inquiries.
      Answers should be helpful and include local keywords.
      
      Format as:
      Q: Question here?
      A: Answer here.
      
      (blank line between pairs)
      `;
      
      suggestions.qa = await callOpenAI(qaPrompt, 'Q&A');
    }
    
    // 6. Review Management (if needed)
    if (scoreData.scores.reviews < 8) {
      const reviewsPrompt = `
      Create a review management strategy for:
      Business: ${businessName}
      Industry: ${industry}
      Location: ${city}, ${state}
      
      Provide:
      - 3 ways to encourage more reviews
      - 2 review request templates (1 follow-up email, 1 text message)
      - Best practices for responding to reviews
      
      Keep it practical and actionable.
      `;
      
      suggestions.reviews = await callOpenAI(reviewsPrompt, 'reviews');
    }
    
    // 7. Citation Building (if needed)
    if (scoreData.scores.citations < 8) {
      const citationsPrompt = `
      Create a citation building strategy for:
      Business: ${businessName}
      Industry: ${industry}
      Location: ${city}, ${state}
      
      Provide:
      - Top 10 citation sources for ${industry} businesses
      - NAP (Name, Address, Phone) consistency checklist
      - Monthly citation building action plan
      
      Focus on industry-specific and local directories.
      `;
      
      suggestions.citations = await callOpenAI(citationsPrompt, 'citations');
    }
    
    // 8. Landing Page Optimization (if needed)
    console.log(`🔍 Landing page score: ${scoreData.scores.landingPage}/8`);
    if (scoreData.scores.landingPage < 8) {
      console.log('🚀 Generating landing page suggestion...');
      const landingPagePrompt = `
      Create a complete localized landing page for:
      Business: ${businessName}
      Industry: ${industry}
      Location: ${city}, ${state}
      Website: ${website}
      
      Provide a ready-to-use landing page with:
      
      1. SUGGESTED URL: Create a SEO-friendly URL path (e.g., /service-city-state)
      
      2. META DESCRIPTION: Write a compelling 150-character meta description that includes the business name, service, and location
      
      3. PAGE COPY: Write complete page content including:
         - Compelling headline with location
         - 2-3 paragraphs about the business serving the local area
         - Why choose this business in this specific location
         - Local trust signals and community connection
         - Clear call-to-action
      
      Format your response clearly with headers for each section.
      Make it conversion-focused and locally relevant.
      `;
      
      try {
        suggestions.landingPage = await callOpenAI(landingPagePrompt, 'landingPage');
      } catch (error) {
        console.error('❌ Landing page suggestion failed:', error.message);
        suggestions.landingPage = {
          title: 'Landing Page Recommendation',
          content: `Create a localized landing page for ${businessName} in ${city}, ${state}. Include your business name and location in the page title, write content about serving the local area, and add local keywords throughout the page.`,
          instructions: 'Create this landing page on your website using local keywords and content.',
          error: 'AI generation failed - using fallback content'
        };
      }
    }

    // 9. Hours of Operation (if needed)
    if (scoreData.scores.hours < 4) {
      const hoursPrompt = `
      Create hours of operation strategy for:
      Business: ${businessName}
      Industry: ${industry}
      Location: ${city}, ${state}

      Provide:
      - Recommended hours for ${industry} businesses
      - Advice on expanding hours to improve rankings
      - Note that being closed during search time hurts rankings
      - Suggest specific days/times to add if possible

      Keep it practical and industry-appropriate.
      `;

      suggestions.hours = await callOpenAI(hoursPrompt, 'hours');
    }

    // 10. Address Visibility (if needed)
    if (scoreData.scores.address < 4) {
      const addressPrompt = `
      Create address visibility strategy for:
      Business: ${businessName}
      Industry: ${industry}

      Provide guidance on:
      - Importance of visible public address for rankings
      - Options if they are a service area business (virtual office, coworking space)
      - Only recommend if they have a real physical location
      - Explain reduced map visibility for service area businesses

      Be realistic about whether they need a physical location.
      `;

      suggestions.address = await callOpenAI(addressPrompt, 'address');
    }

    // 11. Keyword in Business Name (if needed)
    if (scoreData.scores.keywordInName < 4) {
      const keywordInNamePrompt = `
      Create business name keyword strategy for:
      Business: ${businessName}
      Industry: ${industry}

      Provide:
      - Explain why keywords in business name improve rankings
      - Suggest how to add industry keywords to their GBP name
      - IMPORTANT: Warn about Google's rules (must match actual branding/signage)
      - Suggest considering a DBA (Doing Business As) name
      - Examples of compliant vs non-compliant names

      Be clear about Google's guidelines to avoid suspension.
      `;

      suggestions.keywordInName = await callOpenAI(keywordInNamePrompt, 'keyword in name');
    }

    // 12. Services Section (if needed)
    if (scoreData.scores.services < 4) {
      const servicesPrompt = `
      Create Services section strategy for:
      Business: ${businessName}
      Industry: ${industry}
      Location: ${city}, ${state}

      Provide:
      - Generate 5-7 specific service ideas for this business
      - For each service, provide a compelling title and description (100-150 chars)
      - Explain why the Services tab is important for rankings
      - Note that services help capture keyword variations
      - Include pricing strategy advice (whether to show prices)

      Format as a ready-to-use list of services they can add to their GBP.
      `;

      suggestions.services = await callOpenAI(servicesPrompt, 'services');
    }

    console.log(`✅ Smart suggestions generated for ${Object.keys(suggestions).length} areas`);

    return {
      suggestions: suggestions
    };
    
  } catch (error) {
    console.error('❌ Smart suggestions error:', error.message);
    return {
      error: `Smart suggestions failed: ${error.message}`,
      suggestions: {}
    };
  }
}

// Helper function to call OpenAI
async function callOpenAI(prompt, type) {
  try {
    // Use more tokens for landing page content since it needs URL, meta description, and full copy
    const maxTokens = type === 'landingPage' ? 1000 : 500;
    
    const response = await axios.post('https://api.openai.com/v1/chat/completions', {
      model: 'gpt-4o-mini',
      messages: [{
        role: 'user',
        content: prompt
      }],
      max_tokens: maxTokens,
      temperature: 0.7
    }, {
      headers: {
        'Authorization': `Bearer ${OPENAI_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    
    const result = response.data.choices[0].message.content.trim();
    console.log(`✅ Generated ${type}: ${result.length} characters`);
    
    return {
      title: `${type.charAt(0).toUpperCase() + type.slice(1)} Recommendation`,
      content: result,
      instructions: getInstructionsFor(type)
    };
    
  } catch (error) {
    console.error(`❌ OpenAI error for ${type}:`, error.message);
    return {
      title: `${type.charAt(0).toUpperCase() + type.slice(1)} Recommendation`,
      content: `Failed to generate ${type} suggestion`,
      instructions: getInstructionsFor(type),
      error: error.message
    };
  }
}

// Helper function to get instructions
function getInstructionsFor(type) {
  const instructions = {
    'description': 'Copy this description and paste it into your Google Business Profile "About" section.',
    'categories': 'Add these categories in your Google Business Profile > Info > Category section.',
    'product tiles': 'Add these as Products/Services in your Google Business Profile > Products section.',
    'posts': 'Use these as Google Posts - post 1-2 per week for better engagement.',
    'Q&A': 'Add these questions and answers to your Google Business Profile Q&A section.',
    'landingPage': 'Create this landing page on your website using the suggested URL, meta description, and copy provided. This will help you rank for local searches.',
    'citations': 'Submit your business information to the directories listed to improve your local search presence.',
    'reviews': 'Implement these review management strategies to build more positive reviews and respond professionally.'
  };
  
  return instructions[type] || 'Follow Google Business Profile guidelines for implementation.';
}
// ==========================================
// MAIN REPORT GENERATION (COMPLETE VERSION)
// ==========================================

// Fallback functions for failed API calls
function getFallbackBusinessData(businessName, location) {
  return {
    name: businessName,
    phone: '',
    address: location,
    website: '',
    rating: 0,
    reviews: 0,
    verified: false,
    description: '',
    photos_count: 0,
    categories: [],
    hours: null,
    place_id: null,
    google_id: null,
    reviews_link: null
  };
}

function getFallbackCitations() {
  return {
    found: [],
    checked: [],
    total: 7,
    stats: { found: 0, missing: 7, percentage: 0, score: 0 }
  };
}

function getFallbackReviews() {
  return {
    hasRecentReview: false,
    hasBusinessResponses: false,
    reviewCount: 0,
    note: 'Reviews analysis failed'
  };
}

function getFallbackQA() {
  return {
    hasQA: false,
    questionCount: 0,
    questions: [],
    note: 'Q&A analysis failed'
  };
}

function getFallbackWebsite() {
  return {
    hasGBPEmbed: false,
    hasLocalizedPage: false,
    services: [],
    content: '',
    note: 'Website analysis failed'
  };
}

function getFallbackAIAnalysis() {
  return {
    posts: { hasRecent: false, count: 0 },
    productTiles: { hasAny: false, count: 0 },
    qa: { hasAny: false, count: 0 },
    social: { hasAny: false, count: 0 }
  };
}

async function generateCompleteReport(businessName, location, industry, website, user = null, selectedProfile = null) {
  console.log(`🚀 Generating OPTIMIZED report for: ${businessName} in ${location}`);
  
  const errors = [];
  
  try {
    // GROUP 1: Foundation Data (Independent calls)
    console.log('📊 Group 1: Getting foundation data in parallel...');
    const foundationPromises = [];
    
    // Business data (or use selected profile)
    if (selectedProfile && selectedProfile.rawData) {
      console.log(`✅ Using pre-selected profile: ${selectedProfile.name}`);
      const business = selectedProfile.rawData;
      foundationPromises.push(Promise.resolve({
        name: business.name || business.title || businessName,
        phone: business.phone || '',
        address: business.full_address || business.address || '',
        website: business.site || business.website || '',
        rating: parseFloat(business.rating) || 0,
        reviews: parseInt(business.reviews) || parseInt(business.reviews_count) || 0,
        verified: business.verified || business.claimed || false,
        description: business.description || '',
        photos_count: parseInt(business.photos_count) || parseInt(business.photos) || 0,
        categories: business.subtypes ? business.subtypes.split(', ') : (business.type ? [business.type] : []),
        hours: business.working_hours || business.hours || null,
        place_id: business.place_id || business.google_id,
        google_id: business.google_id || business.place_id,
        reviews_link: business.reviews_link
      }));
    } else {
      foundationPromises.push(getOutscraperData(businessName, location));
    }

    // Wait for business data first to get place_id for better screenshot accuracy
    const foundationResults = await Promise.allSettled(foundationPromises);

    // Extract results with fallbacks
    const businessData = foundationResults[0].status === 'fulfilled'
      ? foundationResults[0].value
      : getFallbackBusinessData(businessName, location);

    // Now take screenshot and scrape social links with place_id
    const placeId = businessData.place_id || businessData.google_id;

    // PERFORMANCE OPTIMIZATION: Run screenshot, services screenshot, social scraping, AND citations in parallel
    console.log(`📸 Taking screenshots (main + services), scraping social links, and checking citations in parallel...`);
    const [screenshotResult, servicesScreenshotResult, socialLinksResult, citationsResult] = await Promise.allSettled([
      takeBusinessProfileScreenshot(businessName, location, placeId),
      takeServicesTabScreenshot(businessName, location, placeId),
      scrapeSocialLinksFromGBP(businessName, location, placeId),
      checkCitations(businessName, businessData.phone || '')
    ]);

    let screenshot = null;
    if (screenshotResult.status === 'fulfilled') {
      screenshot = screenshotResult.value;
    } else {
      console.error('❌ Screenshot failed:', screenshotResult.reason?.message);
      errors.push(`Screenshot: ${screenshotResult.reason?.message}`);
    }

    let servicesScreenshot = null;
    if (servicesScreenshotResult.status === 'fulfilled') {
      servicesScreenshot = servicesScreenshotResult.value;
      console.log(`✅ Services screenshot completed`);
    } else {
      console.error('⚠️ Services screenshot failed (non-critical):', servicesScreenshotResult.reason?.message);
    }

    let scrapedSocialLinks = { count: 0, meets2Plus: false, platforms: [] };
    if (socialLinksResult.status === 'fulfilled') {
      scrapedSocialLinks = socialLinksResult.value;
      console.log(`✅ Social link scraping completed: ${scrapedSocialLinks.count} platforms`);
    } else {
      console.error('⚠️ Social link scraping failed (non-critical):', socialLinksResult.reason?.message);
    }

    let citations;
    if (citationsResult.status === 'fulfilled') {
      citations = citationsResult.value;
      console.log(`✅ Citations check completed: ${citations.stats.found}/${citations.total} found`);
    } else {
      console.error('❌ Citation check failed:', citationsResult.reason?.message);
      citations = getFallbackCitations();
      errors.push(`Citations: ${citationsResult.reason?.message}`);
    }

    // Log any foundation failures
    foundationResults.forEach((result, index) => {
      if (result.status === 'rejected') {
        const stepNames = ['Business Data'];
        errors.push(`${stepNames[index]}: ${result.reason?.message || 'Unknown error'}`);
        console.log(`⚠️ ${stepNames[index]} failed: ${result.reason?.message}`);
      }
    });

    console.log(`✅ Group 1 completed: Business data, Screenshot, Social Links, Citations`);

    // GROUP 2: Dependent Analysis (Needs data from Group 1)
    // Q&A removed - no longer available on Google Business Profiles
    console.log('📊 Group 2: Running dependent analysis in parallel...');
    const analysisPromises = [
      analyzeReviews(businessName, location, businessData.place_id),
      analyzeWebsite(businessData.website || website, location)
    ];

    // Add AI analysis if we have screenshot
    if (screenshot && screenshot.filepath) {
      console.log(`🤖 Adding AI screenshot analysis to queue`);
      analysisPromises.push(analyzeScreenshotWithAI(screenshot.filepath, businessName));
    } else {
      console.log(`⚡ Skipping AI analysis (no screenshot available) - using fallback data`);
      analysisPromises.push(Promise.resolve(getFallbackAIAnalysis()));
    }

    // Add Services analysis if we have services screenshot
    if (servicesScreenshot && servicesScreenshot.filepath) {
      console.log(`🛠️ Adding Services screenshot analysis to queue`);
      analysisPromises.push(analyzeServicesFromScreenshot(servicesScreenshot.filepath, businessName));
    } else {
      console.log(`⚡ Skipping Services analysis (no services screenshot available)`);
      analysisPromises.push(Promise.resolve({ hasServices: false, servicesCount: 0, hasDescriptions: false, servicesVisible: [] }));
    }

    const analysisResults = await Promise.allSettled(analysisPromises);

    // Extract analysis results with fallbacks
    const reviewsAnalysis = analysisResults[0].status === 'fulfilled'
      ? analysisResults[0].value
      : getFallbackReviews();

    const websiteAnalysis = analysisResults[1].status === 'fulfilled'
      ? analysisResults[1].value
      : getFallbackWebsite();

    const aiAnalysis = analysisResults[2].status === 'fulfilled'
      ? analysisResults[2].value
      : getFallbackAIAnalysis();

    const servicesAnalysis = analysisResults[3].status === 'fulfilled'
      ? analysisResults[3].value
      : { hasServices: false, servicesCount: 0, hasDescriptions: false, servicesVisible: [] };

    // Log any analysis failures with detailed debugging
    analysisResults.forEach((result, index) => {
      const stepNames = ['Reviews', 'Website', 'AI Analysis', 'Services Analysis'];
      if (result.status === 'rejected') {
        errors.push(`${stepNames[index]}: ${result.reason?.message || 'Unknown error'}`);
        console.log(`❌ ${stepNames[index]} FAILED: ${result.reason?.message}`);
        console.log(`🔍 Full error:`, result.reason);
      } else {
        console.log(`✅ ${stepNames[index]} succeeded`);
      }
    });
    
    console.log(`✅ Group 2 completed: Reviews, Website, AI Analysis`);

    // Merge AI analysis social links with scraped social links for most accurate count
    // Priority: scrapedSocialLinks (from GBP HTML) > AI analysis (from screenshot)
    const mergedSocialLinks = {
      count: Math.max(scrapedSocialLinks.count, aiAnalysis?.socialLinks?.count || 0),
      meets2Plus: scrapedSocialLinks.meets2Plus || aiAnalysis?.socialLinks?.meets2Plus || false,
      platforms: [...new Set([
        ...(scrapedSocialLinks.platforms || []),
        ...(aiAnalysis?.socialLinks?.platforms || [])
      ])],
      links: scrapedSocialLinks.links || {}
    };

    console.log(`🔗 Merged social links: ${mergedSocialLinks.count} platforms (Scraped: ${scrapedSocialLinks.count}, AI: ${aiAnalysis?.socialLinks?.count || 0})`);

    // Compile data for scoring (same as before)
    const partialData = {
      outscraper: businessData,
      screenshot: screenshot,
      aiAnalysis: {
        ...aiAnalysis,
        socialLinks: mergedSocialLinks  // Use merged social links
      },
      citations: citations,
      websiteAnalysis: websiteAnalysis,
      reviewsAnalysis: reviewsAnalysis,
      servicesAnalysis: servicesAnalysis,  // Add services analysis
      scrapedSocialLinks: scrapedSocialLinks  // Keep original for debugging
      // qaAnalysis removed - Q&A no longer available on GBPs
    };

    // Compile data for scoring
    // Transform AI analysis format to match what calculateScore expects
    // DUAL-SOURCE VALIDATION: Use data from either Outscraper OR AI (whichever has it)
    const transformedAiAnalysis = {
      ...partialData.aiAnalysis,
      // Description: Already merged in partialData.aiAnalysis
      description: partialData.aiAnalysis?.description || { exists: false, estimatedLength: 0, meets150Chars: false },

      // Product Tiles: Only AI can detect
      productTiles: {
        hasAny: partialData.aiAnalysis?.productTiles?.meets2Plus || false,
        count: partialData.aiAnalysis?.productTiles?.count || 0,
        meets2Plus: partialData.aiAnalysis?.productTiles?.meets2Plus || false
      },

      // Posts: Prefer AI (has recency data)
      posts: {
        hasRecent: partialData.aiAnalysis?.posts?.meetsLast15Days || false,
        hasAny: partialData.aiAnalysis?.posts?.hasAny || false,
        count: partialData.aiAnalysis?.posts?.count || 0,
        meetsLast15Days: partialData.aiAnalysis?.posts?.meetsLast15Days || false
      },

      // Social: Use MERGED data from both scraped GBP HTML and AI screenshot
      social: {
        hasAny: (partialData.aiAnalysis?.socialLinks?.count || 0) > 0,
        count: partialData.aiAnalysis?.socialLinks?.count || 0,
        platforms: partialData.aiAnalysis?.socialLinks?.platforms || [],
        meets2Plus: partialData.aiAnalysis?.socialLinks?.meets2Plus || false
      },

      // Keep socialLinks for backward compatibility (already merged at line 3275)
      socialLinks: partialData.aiAnalysis?.socialLinks || { count: 0, meets2Plus: false, platforms: [] }
    };

    const compiledData = {
      businessInfo: { businessName, location, industry, website },
      outscraper: partialData.outscraper,
      aiAnalysis: transformedAiAnalysis,
      citations: partialData.citations,
      websiteAnalysis: partialData.websiteAnalysis,
      reviewsAnalysis: partialData.reviewsAnalysis,
      servicesAnalysis: partialData.servicesAnalysis,
      screenshot: partialData.screenshot
      // qaAnalysis removed - Q&A no longer available on GBPs
    };
    
    // Calculate score
    console.log('📊 Calculating score...');
    const scoreData = await calculateScore(compiledData);
    
    // Generate action plan
    console.log('📋 Creating action plan...');
    const actionPlan = generateActionPlan(scoreData);
    
    // GROUP 3: Smart Suggestions
    console.log('🧠 Group 3: Generating smart suggestions...');
    let smartSuggestions;
    
    try {
      // Await the smart suggestions to ensure they're included in the report
      smartSuggestions = await generateSmartSuggestions(
        { businessName, location, industry, website },
        scoreData,
        partialData.websiteAnalysis.services || []
      );
      console.log('✅ Smart suggestions completed successfully');
    } catch (error) {
      console.error('⚠️ Smart suggestions failed (non-critical):', error.message);
      smartSuggestions = { 
        error: error.message,
        message: 'Smart suggestions could not be generated',
        suggestions: {} 
      };
    }
    
    // Build final report (with basic smart suggestions placeholder)
    // Get user-specific branding or use default
    const brandName = (user && user.custom_brand_name) || BRAND_CONFIG.name;
    const brandLogo = (user && user.custom_brand_logo) || BRAND_CONFIG.logo;
    const preparedBy = (user && user.custom_prepared_by) || `${brandName} ${BRAND_CONFIG.preparedBySuffix}`;
    
    const report = {
      success: true,
      business: { name: businessName, location, industry, website },
      auditedProfile: {
        name: partialData.outscraper.name,
        address: partialData.outscraper.address,
        phone: partialData.outscraper.phone,
        website: partialData.outscraper.website,
        verified: partialData.outscraper.verified,
        place_id: partialData.outscraper.place_id
      },
      generatedDate: new Date().toLocaleDateString(),
      brandInfo: {
        name: brandName,
        logo: brandLogo,
        preparedBy: preparedBy
      },
      
      // Audit Overview
      auditOverview: {
        title: "Local SEO Audit Results",
        overallScore: {
          score: scoreData.totalScore,
          maxScore: 100,
          grade: getScoreGrade(scoreData.totalScore),
          message: getScoreMessage(scoreData.totalScore)
        },
        factors: Object.entries(scoreData.scores)
          .filter(([key]) => key !== 'bonus') // Exclude bonus from display
          .map(([key, score]) => ({
            id: key,
            name: formatFactorName(key),
            score: score,
            maxScore: getMaxScore(key),
            status: scoreData.details[key]?.status || 'UNKNOWN',
            message: scoreData.details[key]?.message || ''
          }))
      },
      
      // Smart Suggestions
      smartSuggestions: {
        title: "Smart Optimization Recommendations",
        subtitle: "AI-generated content tailored to your business",
        suggestions: smartSuggestions
      },
      
      // Citations Analysis
      citationsAnalysis: {
        title: "Local Citations Report",
        subtitle: "Your presence across major directories",
        data: partialData.citations,
        recommendations: generateCitationRecommendations(partialData.citations)
      },
      
      // Action Plan
      actionPlan: {
        title: "Priority Action Plan",
        subtitle: "Step-by-step roadmap to improve your local SEO",
        actions: actionPlan
      },
      
      // Technical Details
      technicalDetails: {
        apiCalls: {
          outscraper: partialData.outscraper ? 'SUCCESS' : 'FAILED',
          screenshot: partialData.screenshot ? 'SUCCESS' : 'FAILED',
          aiAnalysis: partialData.aiAnalysis ? 'SUCCESS' : 'FAILED',
          citations: partialData.citations ? 'SUCCESS' : 'FAILED',
          website: partialData.websiteAnalysis ? 'SUCCESS' : 'FAILED',
          reviews: partialData.reviewsAnalysis ? 'SUCCESS' : 'FAILED',
          qaAnalysis: partialData.qaAnalysis ? 'SUCCESS' : 'FAILED'
        },
        errors: errors,
        costs: {
          outscraper: 0.01,
          scrapingbee: partialData.screenshot ? 0.015 : 0,
          openai_analysis: partialData.aiAnalysis ? 0.02 : 0,
          openai_suggestions: Object.keys(smartSuggestions).length * 0.01,
          serpapi_citations: 0.02,
          serpapi_reviews: 0.02,
          serpapi_qa: partialData.qaAnalysis ? 0.02 : 0,
          total: 0.105
        }
      }
    };
    
    console.log(`✅ OPTIMIZED Report generated successfully - Score: ${scoreData.totalScore}/100`);
    console.log(`⚡ Performance: Parallel processing completed in 3 groups`);
    if (errors.length > 0) {
      console.log(`⚠️ ${errors.length} non-critical errors occurred (gracefully handled)`);
    }
    
    return report;
    
  } catch (error) {
    console.error('❌ Critical report generation error:', error);
    throw error;
  }
}

// ==========================================
// HELPER FUNCTIONS
// ==========================================

// Normalize phone number for flexible matching
function normalizePhoneNumber(phone) {
  if (!phone) return '';
  
  // Remove all non-digit characters
  const digitsOnly = phone.replace(/\D/g, '');
  
  // Return just the digits for comparison
  return digitsOnly;
}

// Generate flexible phone number search patterns
function generatePhoneSearchPatterns(phone) {
  if (!phone) return [];
  
  const normalized = normalizePhoneNumber(phone);
  if (normalized.length < 10) return [];
  
  // Extract parts (assuming US phone format)
  const areaCode = normalized.slice(-10, -7);
  const prefix = normalized.slice(-7, -4);
  const number = normalized.slice(-4);
  
  const patterns = [
    // Standard formats
    `(${areaCode}) ${prefix}-${number}`,
    `${areaCode}-${prefix}-${number}`,
    `${areaCode}.${prefix}.${number}`,
    `${areaCode} ${prefix} ${number}`,
    // No separators
    `${areaCode}${prefix}${number}`,
    // Parentheses only around area code
    `(${areaCode})${prefix}-${number}`,
    `(${areaCode}) ${prefix}${number}`,
    // With country code variations
    `1-${areaCode}-${prefix}-${number}`,
    `+1 ${areaCode} ${prefix} ${number}`,
    `+1-${areaCode}-${prefix}-${number}`,
    // Partial matches for citations that might truncate
    `${areaCode}-${prefix}`,
    `(${areaCode}) ${prefix}`,
    // Just the area code and first 3 digits
    `${areaCode}${prefix}`
  ];
  
  return patterns;
}

function getScoreGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function getScoreMessage(score) {
  if (score >= 90) return 'Outstanding! Your local SEO strategy is working beautifully with just minor fine-tuning needed';
  if (score >= 80) return 'Great work! You have a strong foundation with exciting opportunities to reach even more customers';
  if (score >= 70) return 'You\'re on the right track! A few focused improvements will significantly boost your visibility';
  if (score >= 60) return 'Good start! There are several valuable opportunities to enhance your local presence';
  if (score >= 40) return 'You have potential! With some focused effort, you can build a strong local presence';
  return 'Every business starts somewhere! Let\'s work together to build your local SEO success step by step';
}

function formatFactorName(key) {
  const nameMap = {
    claimed: 'Claimed Profile',
    description: 'Business Description',
    categories: 'Categories',
    productTiles: 'Product/Service Tiles',
    photos: 'Photos',
    posts: 'Post Activity',
    qa: 'Q&A Section',
    social: 'Social Media Links',
    reviews: 'Customer Reviews',
    citations: 'Local Citations',
    gbpEmbed: 'GBP Website Embed',
    landingPage: 'Localized Landing Page',
    hours: 'Hours of Operation',
    address: 'Address Visibility',
    keywordInName: 'Keyword in Business Name',
    services: 'Services Section',
    bonus: 'Bonus Points'
  };
  return nameMap[key] || key;
}

function getMaxScore(key) {
  const maxScores = {
    claimed: 4, description: 10, categories: 8, productTiles: 10,
    photos: 8, posts: 6, social: 2,
    reviews: 12, citations: 10, gbpEmbed: 8, landingPage: 8,
    hours: 4, address: 4, keywordInName: 4, services: 4,
    bonus: 7 // Maximum possible bonus points (15 factors / 2, rounded up)
    // Q&A removed (was 4 pts) - no longer available on GBPs
  };
  return maxScores[key] || 0;
}

function generateActionPlan(scoreData) {
  const actions = [];
  
  const actionMap = {
    claimed: { task: 'Claim Google Business Profile', time: '10 minutes', priority: 'CRITICAL' },
    description: { task: 'Optimize Business Description', time: '15 minutes', priority: 'HIGH' },
    categories: { task: 'Add Secondary Categories', time: '10 minutes', priority: 'HIGH' },
    productTiles: { task: 'Add Product/Service Tiles', time: '30 minutes', priority: 'HIGH' },
    photos: { task: 'Upload High-Quality Photos', time: '1 hour', priority: 'MEDIUM' },
    posts: { task: 'Start Weekly Google Posts', time: '15 min/week', priority: 'MEDIUM' },
    hours: { task: 'Add/Expand Hours of Operation', time: '5 minutes', priority: 'HIGH' },
    address: { task: 'Add Public Address (if applicable)', time: '10 minutes', priority: 'MEDIUM' },
    keywordInName: { task: 'Add Industry Keywords to Business Name', time: '30 minutes', priority: 'HIGH' },
    services: { task: 'Add Services Section with Descriptions', time: '45 minutes', priority: 'HIGH' },
    social: { task: 'Add Social Media Links', time: '10 minutes', priority: 'LOW' },
    reviews: { task: 'Implement Review Strategy', time: '2-4 weeks', priority: 'HIGH' },
    citations: { task: 'Build Local Citations', time: '2-4 hours', priority: 'HIGH' },
    gbpEmbed: { task: 'Embed GBP on Website', time: '15 minutes', priority: 'MEDIUM' },
    landingPage: { task: 'Create Localized Landing Page', time: '2-4 hours', priority: 'MEDIUM' }
    // Q&A removed - no longer available on GBPs
  };
  
  Object.entries(scoreData.scores).forEach(([key, score]) => {
    const detail = scoreData.details[key];
    const action = actionMap[key];
    
    if (action && detail) {
      let priority = action.priority;
      if (detail.status === 'GOOD') priority = 'COMPLETE';
      
      actions.push({
        id: key,
        task: action.task,
        completed: detail.status === 'GOOD',
        priority: priority,
        estimatedTime: action.time,
        currentScore: score,
        maxScore: getMaxScore(key),
        message: detail.message
      });
    }
  });
  
  // Sort by priority
  const priorityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'COMPLETE': 0 };
  actions.sort((a, b) => priorityOrder[b.priority] - priorityOrder[a.priority]);
  
  return actions;
}

function generateCitationRecommendations(citationsData) {
  const missing = citationsData.checked.filter(check => !check.found);
  
  return {
    summary: `Found in ${citationsData.stats.found} out of 7 major directories`,
    score: citationsData.stats.score,
    maxScore: 10,
    missingDirectories: missing.map(dir => dir.directory),
    recommendations: missing.length > 0 ? 
      `Focus on getting listed in: ${missing.slice(0, 3).map(dir => dir.directory).join(', ')}` :
      'Excellent citation coverage across all major directories'
  };
}

// ==========================================
// FAST BULK AUDIT FUNCTIONS (OPTIMIZED)
// ==========================================

// Fast parallel citation checker - top 5 directories only
async function checkCitationsFast(businessName, location) {
  try {
    console.log(`🔍 Fast citation check: ${businessName} in ${location}`);

    if (!SERPAPI_KEY) {
      throw new Error('SerpAPI key not configured');
    }

    // Top 5 most important directories
    const directories = [
      { name: 'Yelp', domain: 'yelp.com' },
      { name: 'Yellow Pages', domain: 'yellowpages.com' },
      { name: 'Better Business Bureau', domain: 'bbb.org' },
      { name: 'Facebook Business', domain: 'facebook.com' },
      { name: 'Foursquare', domain: 'foursquare.com' }
    ];

    // Run all citation checks in parallel
    const citationPromises = directories.map(async (directory) => {
      try {
        const searchQuery = `site:${directory.domain} "${businessName}" ${location}`;

        const response = await axios.get('https://serpapi.com/search.json', {
          params: {
            engine: 'google',
            q: searchQuery,
            api_key: SERPAPI_KEY,
            num: 3
          },
          timeout: 8000 // Shorter timeout for speed
        });

        const hasResults = response.data.organic_results && response.data.organic_results.length > 0;

        return {
          directory: directory.name,
          domain: directory.domain,
          found: hasResults,
          url: hasResults ? response.data.organic_results[0]?.link : null
        };

      } catch (dirError) {
        console.error(`❌ Fast citation check failed for ${directory.name}:`, dirError.message);
        return {
          directory: directory.name,
          domain: directory.domain,
          found: false,
          error: dirError.message
        };
      }
    });

    // Wait for all checks to complete
    const checked = await Promise.all(citationPromises);
    const found = checked.filter(check => check.found);

    console.log(`📊 Fast citations: ${found.length}/${directories.length}`);

    return {
      found: found,
      checked: checked,
      total: directories.length,
      stats: {
        found: found.length,
        missing: directories.length - found.length,
        percentage: Math.round((found.length / directories.length) * 100),
        score: found.length * 2 // 2 points per citation
      }
    };

  } catch (error) {
    console.error('❌ Fast citation check error:', error.message);
    throw new Error(`Fast citation check failed: ${error.message}`);
  }
}

// Fast bulk report generation - essential data only
async function generateFastBulkReport(businessName, location, industry, website) {
  console.log(`⚡ Generating FAST report for: ${businessName} in ${location}`);

  // Validate inputs
  if (!businessName || !location || !industry) {
    throw new Error(`Missing required parameters: businessName=${businessName}, location=${location}, industry=${industry}`);
  }

  const errors = [];
  let partialData = {};

  try {
    // Step 1: Get primary business data from Outscraper (keeps all the ranking factors)
    console.log('📍 Step 1: Getting business data...');
    try {
      partialData.outscraper = await getOutscraperData(businessName, location);
      if (!partialData.outscraper) {
        throw new Error('Outscraper returned no data');
      }
    } catch (error) {
      console.error(`⚠️ Outscraper error for ${businessName}:`, error.message);
      errors.push(`Business data: ${error.message}`);
      partialData.outscraper = {
        name: businessName,
        photos: 0,
        photos_count: 0,
        reviews: 0,
        rating: 0,
        categories: [],
        website: website || null,
        address: '',
        phone: '',
        hours: {},
        social: {},
        posts: 0,
        questionsAnswers: 0,
        photoCategories: []
      };
    }

    // Step 2: Take screenshot with place_id for better product tile detection
    console.log('🚀 Step 2: Taking GBP screenshot with place_id...');

    try {
      const placeId = partialData.outscraper?.place_id || partialData.outscraper?.google_id;
      partialData.gbpScreenshot = await takeBusinessProfileScreenshot(businessName, location, placeId);
      console.log(`✅ GBP Screenshot succeeded`);
    } catch (screenshotError) {
      console.error(`❌ GBP Screenshot failed:`, screenshotError.message);
      errors.push(`GBP Screenshot: ${screenshotError.message}`);
      partialData.gbpScreenshot = null;
    }

    // Step 3: AI analysis of GBP screenshot (if available)
    console.log('🤖 Step 3: AI analyzing GBP screenshot...');
    try {
      if (partialData.gbpScreenshot && partialData.gbpScreenshot.filepath) {
        partialData.aiAnalysis = await analyzeScreenshotWithAI(partialData.gbpScreenshot.filepath, businessName);
        console.log(`✅ AI screenshot analysis completed`);

        // If Outscraper failed but AI analysis succeeded, use AI data as fallback for Outscraper
        if (partialData.outscraper && partialData.outscraper.photos_count === 0 && partialData.aiAnalysis) {
          console.log(`🔧 Outscraper had limited data, enriching with AI analysis...`);
          partialData.outscraper.photos_count = partialData.aiAnalysis.photos?.count || 0;
          partialData.outscraper.reviews = partialData.aiAnalysis.reviews?.count || 0;
          partialData.outscraper.rating = partialData.aiAnalysis.reviews?.rating || 0;
          partialData.outscraper.categories = partialData.aiAnalysis.categories?.visible || [];
          partialData.outscraper.description = partialData.aiAnalysis.description?.exists ?
            `[Description present - ${partialData.aiAnalysis.description.estimatedLength} chars]` : '';
        }
      } else {
        console.log(`⚠️ No GBP screenshot available, using fallback data`);
        partialData.aiAnalysis = null;
      }
    } catch (error) {
      errors.push(`AI Analysis: ${error.message}`);
      console.error(`⚠️ AI Analysis error:`, error.message);
      partialData.aiAnalysis = null;
    }

    // Step 4: Analyze website for local landing page (replaces Q&A in bulk audits)
    console.log('🌐 Step 4: Analyzing website for local landing page...');
    try {
      if (website) {
        partialData.websiteAnalysis = await analyzeWebsite(website, location);
        console.log(`✅ Website analysis completed: ${partialData.websiteAnalysis.hasLocalizedPage ? '✅ Has local landing page' : '❌ No local landing page'}`);
      } else {
        console.log('⚠️ No website provided, skipping website analysis');
        partialData.websiteAnalysis = {
          hasGBPEmbed: false,
          hasLocalizedPage: false,
          services: [],
          content: '',
          note: 'No website provided'
        };
      }
    } catch (error) {
      errors.push(`Website Analysis: ${error.message}`);
      console.error(`⚠️ Website analysis error:`, error.message);
      partialData.websiteAnalysis = {
        hasGBPEmbed: false,
        hasLocalizedPage: false,
        services: [],
        content: '',
        note: `Website analysis failed: ${error.message}`
      };
    }

    // Compile essential data for scoring
    const outscraperData = partialData.outscraper || {};
    const aiData = partialData.aiAnalysis || null;

    // Log data source summary for debugging
    console.log(`📊 Data sources for ${businessName}:`, {
      outscraper: outscraperData.photos_count > 0 || outscraperData.reviews > 0 ? '✅' : '❌',
      aiAnalysis: aiData ? '✅' : '❌',
      websiteAnalysis: partialData.websiteAnalysis?.hasLocalizedPage ? '✅' : '❌',
      screenshot: partialData.gbpScreenshot ? '✅' : '❌'
    });

    // Determine which data source to use for the 8 factors
    // Priority: Outscraper API (authoritative) > AI screenshot (visual fallback/supplement)
    const eightFactors = {
      // Description: Prefer Outscraper (complete text), AI can only estimate from screenshot
      description: {
        exists: !!(outscraperData.description && outscraperData.description.length > 0) || aiData?.description?.exists || false,
        estimatedLength: outscraperData.description?.length || aiData?.description?.estimatedLength || 0,
        meets150Chars: (outscraperData.description?.length || aiData?.description?.estimatedLength || 0) >= 150
      },

      // Categories: Prefer Outscraper (has ALL categories), AI only sees visible ones
      categories: {
        count: outscraperData.categories?.length || aiData?.categories?.count || 0,
        meets3Plus: (outscraperData.categories?.length || aiData?.categories?.count || 0) >= 3,
        visible: outscraperData.categories || aiData?.categories?.visible || []
      },

      // Photos: Prefer Outscraper (accurate count), AI estimate from visible gallery
      photos: {
        count: outscraperData.photos_count || aiData?.photos?.count || 0,
        meets10Plus: (outscraperData.photos_count || aiData?.photos?.count || 0) >= 10
      },

      // Reviews: Prefer Outscraper (total count), AI only sees recent visible ones
      reviews: {
        count: outscraperData.reviews || aiData?.reviews?.count || 0,
        rating: outscraperData.rating || aiData?.reviews?.rating || 0,
        meets15Plus: (outscraperData.reviews || aiData?.reviews?.count || 0) >= 15,
        meetsRating4Plus: (outscraperData.rating || aiData?.reviews?.rating || 0) >= 4.0
      },

      // Product Tiles: Only AI can detect (not in Outscraper API)
      productTiles: aiData?.productTiles || {
        count: 0,
        meets2Plus: false
      },

      // Posts: Prefer AI (can check recency), Outscraper only has count
      posts: aiData?.posts || {
        hasAny: (outscraperData.posts || 0) > 0,
        count: outscraperData.posts || 0,
        mostRecentDaysAgo: null,
        meetsLast15Days: false
      },

      // Social Links: Prefer AI (can see visible links), Outscraper may be incomplete
      socialLinks: aiData?.socialLinks || {
        count: outscraperData.social ? Object.keys(outscraperData.social).length : 0,
        meets2Plus: (outscraperData.social ? Object.keys(outscraperData.social).length : 0) >= 2,
        platforms: []
      },

      // Local Landing Page: From website analysis (replaces Q&A for bulk audits)
      localLandingPage: {
        hasPage: partialData.websiteAnalysis?.hasLocalizedPage || false,
        hasGBPEmbed: partialData.websiteAnalysis?.hasGBPEmbed || false,
        note: partialData.websiteAnalysis?.note || 'Not analyzed'
      }
    };

    // Create reviews analysis
    const reviewsAnalysis = {
      totalReviews: eightFactors.reviews.count,
      averageRating: eightFactors.reviews.rating,
      recentReviews: [],
      averageResponseTime: null,
      ownerResponseRate: 0,
      topKeywords: []
    };

    // Structure data to match what calculateScore expects (same as regular audit)
    const compiledData = {
      businessInfo: {
        businessName: businessName,
        location: location,
        industry: industry,
        website: website
      },
      outscraper: outscraperData,
      aiAnalysis: {
        // CRITICAL: Must include ALL factors that calculateScore expects
        description: eightFactors.description,
        categories: eightFactors.categories,
        photos: eightFactors.photos,
        reviews: eightFactors.reviews,
        productTiles: {
          hasAny: eightFactors.productTiles.meets2Plus,
          count: eightFactors.productTiles.count,
          meets2Plus: eightFactors.productTiles.meets2Plus
        },
        posts: {
          hasRecent: eightFactors.posts.meetsLast15Days,
          count: eightFactors.posts.count,
          meetsLast15Days: eightFactors.posts.meetsLast15Days
        },
        social: {
          hasAny: eightFactors.socialLinks.count > 0,
          count: eightFactors.socialLinks.count
        },
        socialLinks: eightFactors.socialLinks
      },
      citations: { found: [], checked: [], total: 0, stats: { found: 0, missing: 0, percentage: 0, score: 0 } },
      websiteAnalysis: partialData.websiteAnalysis || {
        hasGBPEmbed: false,
        hasLocalizedPage: false,
        services: [],
        content: '',
        note: 'Not analyzed'
      },
      reviewsAnalysis: reviewsAnalysis,
      screenshot: partialData.gbpScreenshot?.filepath || null,
      // qaAnalysis removed - Q&A no longer available on GBPs
      eightFactors: eightFactors, // Add the 8 factors for detailed analysis
      errors: errors
    };

    // Calculate score with available data
    console.log('📊 Step 4: Calculating fast score...');
    const scoreData = await calculateScore(compiledData);

    const report = {
      success: true,
      type: 'fast_bulk',
      businessName: businessName,
      location: location,
      industry: industry,
      website: website,
      generatedDate: new Date().toLocaleDateString(),

      // Core data for ranking comparison - 9 FACTORS (includes Claimed Profile)
      coreMetrics: {
        // Factor 0: Claimed Profile (verified/has reviews)
        isClaimed: outscraperData.verified || outscraperData.rating > 0,
        meetsClaimedReq: outscraperData.verified || outscraperData.rating > 0,

        // Factor 1: Description (150+ chars)
        hasDescription: eightFactors.description.exists,
        descriptionLength: eightFactors.description.estimatedLength,
        meetsDescriptionReq: eightFactors.description.meets150Chars,

        // Factor 2: Categories (3+)
        categoriesCount: eightFactors.categories.count,
        meetsCategoriesReq: eightFactors.categories.meets3Plus,

        // Factor 3: Photos (10+)
        photosCount: eightFactors.photos.count,
        meetsPhotosReq: eightFactors.photos.meets10Plus,

        // Factor 4: Reviews (15+, 4.0+ rating)
        reviewsCount: eightFactors.reviews.count,
        averageRating: eightFactors.reviews.rating,
        meetsReviewsReq: eightFactors.reviews.meets15Plus && eightFactors.reviews.meetsRating4Plus,

        // Factor 5: Product/Service Tiles (2+)
        productTilesCount: eightFactors.productTiles.count,
        meetsProductTilesReq: eightFactors.productTiles.meets2Plus,

        // Factor 6: Posts (within 15 days)
        postsCount: eightFactors.posts.count,
        mostRecentPostDays: eightFactors.posts.mostRecentDaysAgo,
        meetsPostsReq: eightFactors.posts.meetsLast15Days,

        // Factor 7: Social Links (2+)
        socialLinksCount: eightFactors.socialLinks.count,
        meetsSocialReq: eightFactors.socialLinks.meets2Plus,
        socialPlatforms: eightFactors.socialLinks.platforms,

        // Factor 8: Local Landing Page - Replaces Q&A in bulk audits
        hasLocalLandingPage: eightFactors.localLandingPage.hasPage,
        hasGBPEmbed: eightFactors.localLandingPage.hasGBPEmbed,
        meetsLocalLandingPageReq: eightFactors.localLandingPage.hasPage,

        // Legacy fields for backward compatibility
        totalReviews: eightFactors.reviews.count,
        totalPhotos: eightFactors.photos.count,
        subcategories: eightFactors.categories.count,
        socialLinks: eightFactors.socialLinks.count,
        questionsAnswers: 0, // Deprecated - replaced with local landing page
        servicesCount: 0, // Deprecated - replaced with local landing page
        posts: eightFactors.posts.count,
        citationsFound: 0,
        hasGBPEmbed: eightFactors.localLandingPage.hasGBPEmbed,
        hasLocalizedPage: eightFactors.localLandingPage.hasPage
      },

      // Scoring
      score: scoreData.totalScore,
      maxScore: scoreData.maxScore,
      scoreBreakdown: scoreData.breakdown,

      // Transform data to match frontend expectations
      data: {
        business: {
          name: compiledData.outscraper?.name || businessName,
          address: compiledData.outscraper?.address || '',
          phone: compiledData.outscraper?.phone || '',
          website: compiledData.outscraper?.website || website || '',
          categories: compiledData.outscraper?.categories || [],
          hours: compiledData.outscraper?.hours || {}
        },
        reviews: {
          total: compiledData.reviewsAnalysis?.totalReviews || 0,
          rating: compiledData.reviewsAnalysis?.averageRating || 0,
          recentReviews: compiledData.reviewsAnalysis?.recentReviews || []
        },
        photos: {
          total: compiledData.outscraper?.photos_count || 0,
          categories: []
        },
        social: compiledData.outscraper?.social || {},
        posts: {
          total: compiledData.aiAnalysis?.posts?.count || 0,
          recent: []
        },
        questionsAnswers: {
          total: compiledData.qaAnalysis?.questionCount || 0,
          answered: 0
        },
        citations: compiledData.citations || { found: [], checked: [], total: 0, stats: { found: 0, missing: 0, percentage: 0, score: 0 } },
        website: {
          hasGBPEmbed: compiledData.websiteAnalysis?.hasGBPEmbed || false,
          hasLocalizedPage: compiledData.websiteAnalysis?.hasLocalizedPage || false,
          services: compiledData.websiteAnalysis?.services || [],
          screenshot: null
        },
        errors: errors
      },

      // Processing info
      processingTime: new Date().toISOString(),
      errors: errors
    };

    console.log(`⚡ Fast report complete: ${businessName} - Score: ${scoreData.totalScore}/${scoreData.maxScore}`);

    return report;

  } catch (error) {
    console.error('❌ Fast bulk report error:', error);
    console.error('❌ Error stack:', error.stack);
    console.error('❌ Partial data state:', JSON.stringify({
      hasOutscraper: !!partialData.outscraper,
      hasCitations: !!partialData.citations,
      hasWebsiteAnalysis: !!partialData.websiteAnalysis,
      errorsCollected: errors
    }, null, 2));
    throw new Error(`Fast report generation failed: ${error.message}`);
  }
}

// Get ranked list of businesses for an industry/location
async function getBusinessRankings(industry, location, count, startFrom) {
  try {
    console.log(`🔍 Getting business rankings for: ${industry} in ${location}`);

    if (!SERPAPI_KEY) {
      throw new Error('SerpAPI key not configured');
    }

    const searchQuery = `${industry} ${location}`;

    const response = await axios.get('https://serpapi.com/search.json', {
      params: {
        engine: 'google_local',
        q: searchQuery,
        api_key: SERPAPI_KEY,
        num: Math.min(startFrom + count, 100) // Get enough results
      },
      timeout: 30000
    });

    if (!response.data.local_results || response.data.local_results.length === 0) {
      throw new Error('No businesses found for this search');
    }

    const allBusinesses = response.data.local_results;

    // Extract businesses from startFrom to startFrom + count
    const selectedBusinesses = allBusinesses
      .slice(startFrom - 1, startFrom - 1 + count)
      .map((business, index) => ({
        rank: startFrom + index,
        name: business.title,
        location: business.address ? `${business.address}, ${location}` : location,
        website: business.website || null,
        phone: business.phone || null,
        rating: business.rating || 0,
        reviews: business.reviews || 0,
        place_id: business.place_id,
        address: business.address
      }));

    console.log(`✅ Retrieved ${selectedBusinesses.length} businesses (ranks ${startFrom}-${startFrom + selectedBusinesses.length - 1})`);

    return selectedBusinesses;

  } catch (error) {
    console.error('❌ Error getting business rankings:', error.message);
    throw error;
  }
}

// Generate competitive analysis
function generateCompetitiveAnalysis(auditResults, industry, location) {
  const scores = auditResults.map(r => r.score);
  const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length;
  const maxScore = Math.max(...scores);
  const minScore = Math.min(...scores);

  // Find correlations between ranking and score
  const topRanked = auditResults.filter(r => r.ranking && r.ranking.position <= 5);
  const avgTopScore = topRanked.length > 0
    ? topRanked.reduce((sum, r) => sum + r.score, 0) / topRanked.length
    : 0;

  // Identify common strengths and weaknesses
  const commonStrengths = analyzeCommonFactors(auditResults, 'strengths');
  const commonWeaknesses = analyzeCommonFactors(auditResults, 'weaknesses');

  return {
    summary: {
      title: `${industry} Competitive Analysis - ${location}`,
      averageScore: Math.round(avgScore),
      highestScore: maxScore,
      lowestScore: minScore,
      topRankedAverage: Math.round(avgTopScore),
      scoreRange: maxScore - minScore,
      totalAnalyzed: auditResults.length
    },
    rankings: {
      byScore: auditResults
        .sort((a, b) => b.score - a.score)
        .map((r, index) => ({
          scoreRank: index + 1,
          googleRank: r.ranking ? r.ranking.position : null,
          businessName: r.businessName,
          score: r.score,
          rankDifference: r.ranking ? (r.ranking.position - (index + 1)) : null // How Google rank differs from SEO score rank
        })),
      insights: generateRankingInsights(auditResults)
    },
    commonStrengths: commonStrengths,
    commonWeaknesses: commonWeaknesses,
    marketGaps: identifyMarketGaps(auditResults)
  };
}

// Calculate industry benchmarks
function calculateIndustryBenchmarks(auditResults) {
  const factors = [
    'claimed', 'description', 'categories', 'productTiles',
    'photos', 'posts', 'qa', 'social',
    'reviews', 'citations', 'gbpEmbed', 'landingPage'
  ];

  const benchmarks = {};

  factors.forEach(factor => {
    const scores = auditResults.map(r => {
      const factorData = r.scoreBreakdown && r.scoreBreakdown.factors ?
        r.scoreBreakdown.factors.find(f => f.id === factor) : null;
      return factorData ? factorData.score : 0;
    });
    const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
    const max = Math.max(...scores);

    benchmarks[factor] = {
      name: formatFactorName(factor),
      average: Math.round(avg * 10) / 10,
      best: max,
      percentAchieving: Math.round((scores.filter(s => s === max).length / scores.length) * 100)
    };
  });

  return benchmarks;
}

// Identify opportunities in the market
function identifyOpportunities(auditResults) {
  const opportunities = [];

  // Find businesses with high rankings but low scores (vulnerable competitors)
  const vulnerableCompetitors = auditResults.filter(r => {
    const rank = r.ranking ? r.ranking.position : 999;
    return rank <= 10 && r.score < 60;
  });

  if (vulnerableCompetitors.length > 0) {
    opportunities.push({
      type: 'VULNERABLE_COMPETITORS',
      priority: 'HIGH',
      message: `${vulnerableCompetitors.length} top-ranked businesses have low SEO scores (under 60)`,
      businesses: vulnerableCompetitors.map(r => ({
        name: r.businessName,
        rank: r.ranking ? r.ranking.position : null,
        score: r.score
      })),
      actionable: 'These businesses are vulnerable to optimization - focus on outscoring them'
    });
  }

  // Find common gaps across all competitors
  const gapAnalysis = findCommonGaps(auditResults);

  if (gapAnalysis.length > 0) {
    opportunities.push({
      type: 'INDUSTRY_GAPS',
      priority: 'MEDIUM',
      message: 'Industry-wide optimization gaps identified',
      gaps: gapAnalysis,
      actionable: 'Excel in these areas where most competitors are weak'
    });
  }

  // Find ranking opportunities (large score vs rank discrepancies)
  const underperformers = auditResults.filter(r => {
    if (!r.ranking) return false;
    const scoreRank = auditResults.filter(x => x.score > r.score).length + 1;
    return r.ranking.position - scoreRank > 5; // Ranking 5+ positions worse than their score suggests
  });

  if (underperformers.length > 0) {
    opportunities.push({
      type: 'RANKING_OPPORTUNITIES',
      priority: 'HIGH',
      message: `${underperformers.length} businesses ranking below their optimization level`,
      businesses: underperformers.map(r => ({
        name: r.businessName,
        rank: r.ranking ? r.ranking.position : null,
        score: r.score
      })),
      actionable: 'These positions are achievable with proper optimization'
    });
  }

  return opportunities;
}

// Helper function to analyze common factors
function analyzeCommonFactors(auditResults, type) {
  const factors = {};

  auditResults.forEach(result => {
    if (!result.scoreBreakdown || !result.scoreBreakdown.factors) return;

    result.scoreBreakdown.factors.forEach(factor => {
      if (!factors[factor.id]) {
        factors[factor.id] = { scores: [], statuses: [] };
      }
      factors[factor.id].scores.push(factor.score);
      factors[factor.id].statuses.push(factor.status);
    });
  });

  const analysis = [];

  Object.entries(factors).forEach(([factorId, data]) => {
    const avgScore = data.scores.reduce((a, b) => a + b, 0) / data.scores.length;
    const goodCount = data.statuses.filter(s => s === 'GOOD').length;
    const totalCount = data.statuses.length;
    const goodPercentage = (goodCount / totalCount) * 100;

    if (type === 'strengths' && goodPercentage >= 60) {
      analysis.push({
        factor: formatFactorName(factorId),
        percentage: Math.round(goodPercentage),
        avgScore: Math.round(avgScore * 10) / 10,
        message: `${Math.round(goodPercentage)}% of businesses excel in this area`
      });
    } else if (type === 'weaknesses' && goodPercentage <= 30) {
      analysis.push({
        factor: formatFactorName(factorId),
        percentage: Math.round(goodPercentage),
        avgScore: Math.round(avgScore * 10) / 10,
        message: `Only ${Math.round(goodPercentage)}% of businesses handle this well`
      });
    }
  });

  return analysis.sort((a, b) => type === 'strengths' ? b.percentage - a.percentage : a.percentage - b.percentage);
}

// Generate ranking insights
function generateRankingInsights(auditResults) {
  const insights = [];

  // Check correlation between scores and rankings
  const correlation = calculateRankScoreCorrelation(auditResults);

  if (correlation < -0.3) {
    insights.push({
      type: 'STRONG_CORRELATION',
      message: 'Higher SEO scores strongly correlate with better rankings in this market'
    });
  } else {
    insights.push({
      type: 'WEAK_CORRELATION',
      message: 'Other factors beyond SEO optimization may influence rankings here'
    });
  }

  // Find outliers
  const outliers = findRankingOutliers(auditResults);
  if (outliers.overperformers.length > 0) {
    insights.push({
      type: 'OVERPERFORMERS',
      message: `${outliers.overperformers.length} businesses ranking better than their SEO score suggests`,
      businesses: outliers.overperformers
    });
  }

  return insights;
}

// Calculate correlation between rank and score
function calculateRankScoreCorrelation(auditResults) {
  const validResults = auditResults.filter(r => r.ranking && r.ranking.position);
  if (validResults.length === 0) return 0;

  const n = validResults.length;
  const ranks = validResults.map(r => r.ranking.position);
  const scores = validResults.map(r => r.score);

  const avgRank = ranks.reduce((a, b) => a + b, 0) / n;
  const avgScore = scores.reduce((a, b) => a + b, 0) / n;

  let numerator = 0;
  let denomRank = 0;
  let denomScore = 0;

  for (let i = 0; i < n; i++) {
    const rankDiff = ranks[i] - avgRank;
    const scoreDiff = scores[i] - avgScore;
    numerator += rankDiff * scoreDiff;
    denomRank += rankDiff * rankDiff;
    denomScore += scoreDiff * scoreDiff;
  }

  return numerator / Math.sqrt(denomRank * denomScore);
}

// Find ranking outliers
function findRankingOutliers(auditResults) {
  const validResults = auditResults.filter(r => r.ranking && r.ranking.position);

  const scoreRanks = validResults
    .map((r, i) => ({ ...r, scoreRank: i + 1 }))
    .sort((a, b) => b.score - a.score)
    .map((r, i) => ({ ...r, scoreRank: i + 1 }));

  const overperformers = scoreRanks
    .filter(r => r.scoreRank - r.ranking.position > 5)
    .map(r => ({ name: r.businessName, rank: r.ranking.position, score: r.score }));

  const underperformers = scoreRanks
    .filter(r => r.ranking.position - r.scoreRank > 5)
    .map(r => ({ name: r.businessName, rank: r.ranking.position, score: r.score }));

  return { overperformers, underperformers };
}

// Identify market gaps
function identifyMarketGaps(auditResults) {
  const gaps = [];

  // Check what percentage lacks each feature
  const featureAdoption = {};

  auditResults.forEach(result => {
    if (!result.scoreBreakdown || !result.scoreBreakdown.factors) return;

    result.scoreBreakdown.factors.forEach(factor => {
      if (!featureAdoption[factor.id]) {
        featureAdoption[factor.id] = { total: 0, good: 0 };
      }
      featureAdoption[factor.id].total++;
      if (factor.status === 'GOOD') {
        featureAdoption[factor.id].good++;
      }
    });
  });

  Object.entries(featureAdoption).forEach(([factorId, data]) => {
    const adoptionRate = (data.good / data.total) * 100;
    if (adoptionRate < 40) {
      gaps.push({
        factor: formatFactorName(factorId),
        adoptionRate: Math.round(adoptionRate),
        opportunity: `${Math.round(100 - adoptionRate)}% of competitors are missing this`
      });
    }
  });

  return gaps.sort((a, b) => a.adoptionRate - b.adoptionRate);
}

// Find common gaps across reports
function findCommonGaps(auditResults) {
  const gapCounts = {};

  auditResults.forEach(result => {
    if (!result.scoreBreakdown || !result.scoreBreakdown.factors) return;

    result.scoreBreakdown.factors.forEach(factor => {
      if (factor.status !== 'GOOD') {
        if (!gapCounts[factor.id]) {
          gapCounts[factor.id] = 0;
        }
        gapCounts[factor.id]++;
      }
    });
  });

  const totalReports = auditResults.length;
  const commonGaps = [];

  Object.entries(gapCounts).forEach(([factorId, count]) => {
    const percentage = (count / totalReports) * 100;
    if (percentage >= 70) {
      commonGaps.push({
        factor: formatFactorName(factorId),
        percentage: Math.round(percentage),
        message: `${Math.round(percentage)}% of businesses are missing this`
      });
    }
  });

  return commonGaps.sort((a, b) => b.percentage - a.percentage);
}

// ==========================================
// API ROUTES
// ==========================================

// Basic routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Local SEO Audit v3 is working!', 
    timestamp: new Date(),
    version: '3.0',
    brand: BRAND_CONFIG,
    apis: {
      outscraper: !!OUTSCRAPER_API_KEY,
      scrapingbee: !!SCRAPINGBEE_API_KEY,
      openai: !!OPENAI_API_KEY,
      serpapi: !!SERPAPI_KEY
    }
  });
});

// Authentication routes
app.post('/api/signup', authLimiter, async (req, res) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    
    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }

    // Validate password strength
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({ error: passwordValidation.error });
    }
    
    // Check if user already exists
    const existingUser = await db.get('SELECT id FROM users WHERE email = $1', [email]);
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }
    
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Generate email verification token
    const verificationToken = generateSecureToken();
    const verificationExpires = new Date();
    verificationExpires.setHours(verificationExpires.getHours() + 24); // 24 hour expiry
    
    // Insert new user with RETURNING clause for PostgreSQL compatibility
    const insertQuery = db.dbType === 'postgresql' 
      ? 'INSERT INTO users (email, password_hash, first_name, last_name, email_verification_token, email_verification_expires) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id'
      : 'INSERT INTO users (email, password_hash, first_name, last_name, email_verification_token, email_verification_expires) VALUES ($1, $2, $3, $4, $5, $6)';
    
    const result = await db.run(insertQuery, [email, passwordHash, firstName, lastName, verificationToken, verificationExpires]);
    const userId = result.lastID || result.rows?.[0]?.id;
    
    if (!userId) {
      throw new Error('Failed to get user ID after insert');
    }
    
    const token = jwt.sign({ userId: userId }, JWT_SECRET, { expiresIn: '7d' });
    
    console.log(`✅ New user created: ${email} (ID: ${userId})`);
    
    // Send verification email
    try {
      await sendVerificationEmail(email, firstName, verificationToken);
      console.log(`📧 Verification email sent to ${email}`);
    } catch (emailError) {
      console.error('Failed to send verification email:', emailError);
      // Don't fail the signup if email fails
    }
    
    // Send notification for new user
    try {
      await sendNewUserNotification({
        userId,
        email,
        firstName,
        lastName,
        signupDate: new Date().toISOString(),
        plan: 'free',
        initialCredits: 1
      });
    } catch (notifyError) {
      console.error('Failed to send new user notification:', notifyError);
      // Don't fail the signup if notification fails
    }
    
    res.json({
      success: true,
      token,
      user: {
        id: userId,
        email: email,
        firstName: firstName,
        lastName: lastName,
        creditsRemaining: 1,
        subscriptionTier: 'free',
        emailVerified: false
      },
      message: 'Account created successfully. Please check your email to verify your account.'
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

// AppSumo code redemption endpoint
app.post('/api/redeem-appsumo', authenticateToken, async (req, res) => {
  try {
    const { code } = req.body;

    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'AppSumo code is required' });
    }

    const cleanCode = code.trim().toUpperCase();

    // Check if code exists and is not redeemed
    const appsumoCode = await db.get(
      'SELECT * FROM appsumo_codes WHERE code = $1',
      [cleanCode]
    );

    if (!appsumoCode) {
      return res.status(404).json({ error: 'Invalid AppSumo code' });
    }

    if (appsumoCode.is_redeemed) {
      return res.status(400).json({ error: 'This code has already been redeemed' });
    }

    // Check if user already has a lifetime plan
    if (req.user.is_lifetime) {
      return res.status(400).json({ error: 'You already have a lifetime plan active' });
    }

    // Activate lifetime plan for user
    await db.query(
      `UPDATE users SET
        appsumo_code = $1,
        appsumo_plan_id = $2,
        is_lifetime = $3,
        lifetime_monthly_credits = $4,
        credits_remaining = $5,
        subscription_tier = $6,
        last_credit_renewal = NOW()
      WHERE id = $7`,
      [
        cleanCode,
        appsumoCode.plan_id,
        true,
        appsumoCode.monthly_credits,
        appsumoCode.monthly_credits, // Give them their first month immediately
        appsumoCode.plan_name,
        req.user.id
      ]
    );

    // Mark code as redeemed
    await db.query(
      `UPDATE appsumo_codes SET
        is_redeemed = $1,
        redeemed_by_user_id = $2,
        redeemed_at = NOW()
      WHERE id = $3`,
      [true, req.user.id, appsumoCode.id]
    );

    console.log(`✅ AppSumo code redeemed: ${cleanCode} by user ${req.user.email}`);

    res.json({
      success: true,
      message: `Lifetime plan activated! You now have ${appsumoCode.monthly_credits} credits per month for life.`,
      plan: {
        name: appsumoCode.plan_name,
        monthlyCredits: appsumoCode.monthly_credits,
        creditsNow: appsumoCode.monthly_credits
      }
    });

  } catch (error) {
    console.error('AppSumo redemption error:', error);
    res.status(500).json({ error: 'Failed to redeem AppSumo code' });
  }
});

// Email verification endpoint
app.get('/api/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    
    if (!token) {
      return res.status(400).json({ error: 'Verification token is required' });
    }
    
    // Find user with this token
    const user = await db.get(
      'SELECT * FROM users WHERE email_verification_token = $1 AND email_verification_expires > $2',
      [token, new Date()]
    );
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }
    
    // Update user as verified
    await db.run(
      'UPDATE users SET email_verified = $1, email_verification_token = NULL, email_verification_expires = NULL WHERE id = $2',
      [db.dbType === 'postgresql' ? true : 1, user.id]
    );
    
    console.log(`✅ Email verified for user: ${user.email}`);
    
    res.json({
      success: true,
      message: 'Email verified successfully! You can now log in to your account.'
    });
  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ error: 'Failed to verify email' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    const user = await db.get('SELECT * FROM users WHERE email = $1', [email]);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    
    console.log(`✅ User logged in: ${email}`);
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        creditsRemaining: user.credits_remaining,
        subscriptionTier: user.subscription_tier,
        emailVerified: db.dbType === 'postgresql' ? user.email_verified : user.email_verified === 1
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Password reset request endpoint
app.post('/api/forgot-password', resetLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    // Find user by email
    const user = await db.get('SELECT * FROM users WHERE email = $1', [email]);
    
    if (!user) {
      // Don't reveal if user exists or not for security
      return res.json({
        success: true,
        message: 'If an account exists with this email, you will receive password reset instructions.'
      });
    }
    
    // Generate password reset token
    const resetToken = generateSecureToken();
    const resetExpires = new Date();
    resetExpires.setHours(resetExpires.getHours() + 1); // 1 hour expiry
    
    // Update user with reset token
    await db.run(
      'UPDATE users SET password_reset_token = $1, password_reset_expires = $2 WHERE id = $3',
      [resetToken, resetExpires, user.id]
    );
    
    // Send password reset email
    try {
      await sendPasswordResetEmail(user.email, user.first_name, resetToken);
      console.log(`📧 Password reset email sent to ${user.email}`);
    } catch (emailError) {
      console.error('Failed to send password reset email:', emailError);
      // Don't reveal email sending failure to user
    }
    
    res.json({
      success: true,
      message: 'If an account exists with this email, you will receive password reset instructions.'
    });
  } catch (error) {
    console.error('Password reset request error:', error);
    res.status(500).json({ error: 'Failed to process password reset request' });
  }
});

// Password reset endpoint
app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }

    // Validate password strength
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.valid) {
      return res.status(400).json({ error: passwordValidation.error });
    }
    
    // Find user with valid reset token
    const user = await db.get(
      'SELECT * FROM users WHERE password_reset_token = $1 AND password_reset_expires > $2',
      [token, new Date()]
    );
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    // Hash new password
    const passwordHash = await bcrypt.hash(newPassword, 10);
    
    // Update password and clear reset token
    await db.run(
      'UPDATE users SET password_hash = $1, password_reset_token = NULL, password_reset_expires = NULL WHERE id = $2',
      [passwordHash, user.id]
    );
    
    console.log(`✅ Password reset for user: ${user.email}`);
    
    res.json({
      success: true,
      message: 'Password reset successfully! You can now log in with your new password.'
    });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Resend verification email endpoint
app.post('/api/resend-verification', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    
    // Check if user is already verified
    const emailVerified = db.dbType === 'postgresql' ? user.email_verified : user.email_verified === 1;
    if (emailVerified) {
      return res.status(400).json({ error: 'Email is already verified' });
    }
    
    // Generate new verification token
    const verificationToken = generateSecureToken();
    const verificationExpires = new Date();
    verificationExpires.setHours(verificationExpires.getHours() + 24); // 24 hour expiry
    
    // Update user with new token
    await db.run(
      'UPDATE users SET email_verification_token = $1, email_verification_expires = $2 WHERE id = $3',
      [verificationToken, verificationExpires, user.id]
    );
    
    // Send verification email
    try {
      await sendVerificationEmail(user.email, user.first_name, verificationToken);
      console.log(`📧 Resent verification email to ${user.email}`);
    } catch (emailError) {
      console.error('Failed to resend verification email:', emailError);
      return res.status(500).json({ error: 'Failed to send verification email' });
    }
    
    res.json({
      success: true,
      message: 'Verification email sent successfully'
    });
  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ error: 'Failed to resend verification email' });
  }
});

app.get('/api/profile', authenticateToken, (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
      firstName: req.user.first_name,
      lastName: req.user.last_name,
      creditsRemaining: req.user.credits_remaining,
      subscriptionTier: req.user.subscription_tier,
      emailVerified: db.dbType === 'postgresql' ? req.user.email_verified : req.user.email_verified === 1
    }
  });
});

// COMPLETE REPORT GENERATION FOR PRODUCTION
// Profile verification endpoint - returns multiple profile options for user selection
app.post('/api/verify-profile', authenticateToken, async (req, res) => {
  try {
    console.log(`🔍 Profile verification request from user ${req.user.email}`);
    const { businessName, location } = req.body;
    
    if (!businessName || !location) {
      return res.status(400).json({ error: 'Business name and location are required' });
    }
    
    console.log(`🔍 Searching for profiles: ${businessName} in ${location}`);
    
    const profileOptions = await getBusinessProfileOptions(businessName, location);
    
    console.log(`✅ Found ${profileOptions.length} profile options`);
    
    res.json({
      success: true,
      profiles: profileOptions,
      searchQuery: { businessName, location }
    });
    
  } catch (error) {
    console.error('❌ Profile verification error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch business profiles', 
      details: error.message 
    });
  }
});

// Generate a minimal locked report when the main report generation fails
async function generateFallbackLockedReport(businessName, location, industry, website, user = null) {
  console.log(`🔒 Generating fallback locked report for: ${businessName} in ${location}`);
  
  // Get user-specific branding or use default
  const brandName = (user && user.custom_brand_name) || BRAND_CONFIG.name;
  const brandLogo = (user && user.custom_brand_logo) || BRAND_CONFIG.logo;
  const preparedBy = (user && user.custom_prepared_by) || `${brandName} ${BRAND_CONFIG.preparedBySuffix}`;
  
  // Create minimal report structure with locked data
  const fallbackReport = {
    success: true,
    business: { name: businessName, location, industry, website },
    auditedProfile: {
      name: businessName,
      address: location,
      phone: 'Data locked - upgrade to view',
      website: website || 'Data locked - upgrade to view',
      verified: false,
      place_id: null
    },
    generatedDate: new Date().toLocaleDateString(),
    brandInfo: {
      name: brandName,
      logo: brandLogo,
      preparedBy: preparedBy
    },
    
    // Basic audit overview with locked score
    auditOverview: {
      title: "Local SEO Audit Results",
      overallScore: {
        score: 0,
        maxScore: 100,
        grade: 'LOCKED',
        message: 'Upgrade to see your Local SEO score and detailed analysis'
      },
      factors: [
        { id: 'profile_completeness', name: 'Profile Completeness', score: 0, maxScore: 20, status: 'LOCKED', message: 'Upgrade to view analysis' },
        { id: 'reviews_engagement', name: 'Reviews & Engagement', score: 0, maxScore: 15, status: 'LOCKED', message: 'Upgrade to view analysis' },
        { id: 'citation_consistency', name: 'Citation Consistency', score: 0, maxScore: 20, status: 'LOCKED', message: 'Upgrade to view analysis' },
        { id: 'local_content', name: 'Local Content', score: 0, maxScore: 15, status: 'LOCKED', message: 'Upgrade to view analysis' },
        { id: 'visual_content', name: 'Visual Content', score: 0, maxScore: 10, status: 'LOCKED', message: 'Upgrade to view analysis' },
        { id: 'website_optimization', name: 'Website Optimization', score: 0, maxScore: 10, status: 'LOCKED', message: 'Upgrade to view analysis' },
        { id: 'customer_engagement', name: 'Customer Engagement', score: 0, maxScore: 10, status: 'LOCKED', message: 'Upgrade to view analysis' }
      ]
    },
    
    // Locked sections
    smartSuggestions: {
      locked: true,
      message: 'Upgrade to unlock personalized AI recommendations'
    },
    actionPlan: {
      locked: true,
      message: 'Upgrade to unlock your step-by-step action plan'
    },
    citationsAnalysis: {
      locked: true,
      message: 'Upgrade to unlock detailed citation analysis'
    },
    competitorAnalysis: {
      locked: true,
      message: 'Upgrade to unlock competitor insights'
    },
    
    // Error tracking
    errors: ['Report generation failed - showing locked preview'],
    
    // Mark as fallback
    isFallback: true
  };
  
  console.log(`✅ Fallback locked report generated for ${businessName}`);
  return fallbackReport;
}

app.post('/api/generate-report', reportLimiter, authenticateToken, async (req, res) => {
  try {
    console.log(`📊 Report request from user ${req.user.email}`);
    console.log('🔍 DEBUG: Request body:', req.body);
    
    // Handle both old and new frontend formats, plus selected profile data
    const { businessName, location, city, industry, category, website, selectedProfile } = req.body;
    const finalLocation = location || city;
    const finalIndustry = industry || category;
    
    if (!businessName || !finalLocation || !finalIndustry) {
      return res.status(400).json({ error: 'Business name, location, and industry are required' });
    }
    
    // Validate location format - more flexible for international addresses
    // Allow formats like "City, ST", "City - Country", or complex addresses
    if (finalLocation.length < 3) {
      return res.status(400).json({ error: 'Please provide a valid location (e.g., "Denver, CO" or "Dubai, UAE")' });
    }
    
    // CRITICAL FIX: Deduct credit BEFORE generating report to prevent race conditions
    let hasCredits = false;
    if (req.user.credits_remaining > 0) {
      try {
        // Atomic credit deduction with verification
        const result = await db.query(
          'UPDATE users SET credits_remaining = credits_remaining - 1 WHERE id = $1 AND credits_remaining > 0 RETURNING credits_remaining',
          [req.user.id]
        );
        
        if (result.rows && result.rows.length > 0) {
          hasCredits = true;
          const newCredits = result.rows[0].credits_remaining;
          console.log(`💳 Credit deducted. User now has ${newCredits} credits remaining`);
        } else {
          console.log(`❌ Credit deduction failed - user may have run out of credits during processing`);
          hasCredits = false;
        }
      } catch (err) {
        console.error('Error deducting credits:', err);
        hasCredits = false;
      }
    } else {
      console.log(`👀 Preview report requested for user without credits: ${req.user.email}`);
    }
    
    console.log(`🏢 Generating ${hasCredits ? 'COMPLETE' : 'LOCKED'} report for: ${businessName} in ${finalLocation} (${finalIndustry})`);
    
    let report;
    try {
      // Generate complete report with all features
      report = await generateCompleteReport(businessName, finalLocation, finalIndustry, website, req.user, selectedProfile);
    } catch (reportError) {
      console.error('❌ Report generation failed, creating fallback locked report:', reportError);
      
      // If report generation fails for users without credits, create a minimal locked report
      if (!hasCredits) {
        console.log('🔒 Creating fallback locked report for user without credits');
        report = await generateFallbackLockedReport(businessName, finalLocation, finalIndustry, website, req.user);
      } else {
        // If user paid for the report but it failed, refund the credit and throw error
        console.log('💰 Refunding credit due to report generation failure');
        try {
          await db.query(
            'UPDATE users SET credits_remaining = credits_remaining + 1 WHERE id = $1',
            [req.user.id]
          );
          console.log('✅ Credit refunded successfully');
        } catch (refundError) {
          console.error('❌ Failed to refund credit:', refundError);
        }
        throw reportError;
      }
    }
    
    // Save report
    let savedReportId = null;
    try {
      // Try with was_paid column first, fallback if column doesn't exist
      let result;
      try {
        result = await db.query(
          'INSERT INTO reports (user_id, business_name, city, industry, website, report_data, was_paid) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
          [req.user.id, businessName, finalLocation, finalIndustry, website || null, JSON.stringify(report), hasCredits]
        );
      } catch (error) {
        if (error.message.includes('was_paid') && error.message.includes('does not exist')) {
          console.log('⚠️ was_paid column missing, using fallback insert');
          result = await db.query(
            'INSERT INTO reports (user_id, business_name, city, industry, website, report_data) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
            [req.user.id, businessName, finalLocation, finalIndustry, website || null, JSON.stringify(report)]
          );
        } else {
          throw error;
        }
      }
      savedReportId = result.rows?.[0]?.id || null;
      console.log(`💾 Report saved with ID: ${savedReportId}`);
    } catch (err) {
      console.error('Error saving report:', err);
    }

    // Calculate optimization opportunities if the report is locked
    let optimizationOpportunities = 0;
    if (!hasCredits && report.auditOverview && report.auditOverview.factors) {
      optimizationOpportunities = report.auditOverview.factors.filter(factor => 
        factor.status === 'MISSING' || factor.status === 'NEEDS IMPROVEMENT'
      ).length;
    }

    console.log(`✅ ${hasCredits ? 'COMPLETE' : 'LOCKED'} Report generated successfully for ${businessName}`);
    
    // Add locked status and optimization count to response
    const responseReport = {
      ...report,
      isLocked: !hasCredits,
      optimizationOpportunities: hasCredits ? 0 : optimizationOpportunities,
      reportId: savedReportId
    };
    
    res.json({
      success: true,
      report: responseReport
    });
    
  } catch (error) {
    console.error('❌ Report generation error:', error);
    res.status(500).json({ 
      error: 'Failed to generate report. Please try again.'
    });
  }
});

// Fast Bulk Scan endpoint - optimized for speed
app.post('/api/generate-fast-bulk-scan', authenticateToken, async (req, res) => {
  try {
    const { industry, location, count, startFrom } = req.body;

    // Validation
    if (!industry || !location || !count) {
      return res.status(400).json({ error: 'Industry, location, and count are required' });
    }

    if (count < 1 || count > 25) {
      return res.status(400).json({ error: 'Count must be between 1 and 25' });
    }

    const actualStartFrom = startFrom || 1;
    const creditsNeeded = count;

    if (req.user.credits_remaining < creditsNeeded) {
      return res.status(402).json({
        error: `Insufficient credits. This fast bulk scan requires ${creditsNeeded} credits. You have ${req.user.credits_remaining}.`
      });
    }

    console.log(`⚡ Starting FAST bulk scan: ${industry} in ${location}, ${count} businesses starting from #${actualStartFrom}`);

    // Get ranked list of businesses
    const businessList = await getBusinessRankings(industry, location, count, actualStartFrom);

    if (!businessList || businessList.length === 0) {
      return res.status(404).json({ error: 'No businesses found for this industry/location' });
    }

    console.log(`📋 Found ${businessList.length} businesses for fast scan`);

    // Run fast audits with progress tracking - PARALLEL PROCESSING (3 at a time)
    const auditResults = [];
    const errors = [];
    let creditsUsed = 0;
    const CONCURRENCY_LIMIT = 3; // Process 3 businesses at a time

    // Helper function to process a single business
    const processBusiness = async (business, index) => {
      console.log(`\n⚡ Fast scanning ${index + 1}/${businessList.length}: ${business.name} (Rank #${business.rank})`);

      try {
        // Generate FAST report for this business
        const report = await generateFastBulkReport(
          business.name,
          business.location || location,
          industry,
          business.website
        );

        // Add ranking information
        report.ranking = {
          position: business.rank,
          searchTerm: `${industry} ${location}`,
          url: business.website
        };

        console.log(`✅ Fast scan complete: ${business.name} - Score: ${report.score}/${report.maxScore}`);
        return { success: true, report, business };

      } catch (businessError) {
        console.error(`❌ Fast scan failed for ${business.name}:`, businessError.message);
        console.error(`❌ Error stack:`, businessError.stack);

        const error = {
          business: business.name,
          rank: business.rank,
          error: businessError.message,
          details: businessError.stack
        };

        // Create a minimal fallback report for failed businesses
        const fallbackReport = {
          success: false,
          type: 'fast_bulk',
          businessName: business.name,
          location: location,
          industry: industry,
          website: business.website || null,
          ranking: {
            position: business.rank,
            searchTerm: `${industry} ${location}`,
            url: business.website
          },
          score: 0,
          maxScore: 100,
          coreMetrics: {
            totalReviews: 0,
            averageRating: 0,
            totalPhotos: 0,
            subcategories: 0,
            socialLinks: 0,
            questionsAnswers: 0, // Deprecated
            servicesCount: 0,
            posts: 0,
            citationsFound: 0,
            hasGBPEmbed: false,
            hasLocalizedPage: false
          },
          data: {
            business: {
              name: business.name,
              address: '',
              phone: '',
              website: business.website || '',
              categories: [],
              hours: {}
            },
            reviews: { total: 0, rating: 0, recentReviews: [] },
            photos: { total: 0, categories: [] },
            social: {},
            posts: { total: 0, recent: [] },
            questionsAnswers: { total: 0, answered: 0 },
            citations: { found: [], checked: [], total: 0, stats: { found: 0, missing: 0, percentage: 0, score: 0 } },
            website: { hasGBPEmbed: false, hasLocalizedPage: false, services: [], screenshot: null },
            errors: [businessError.message]
          },
          errors: [businessError.message],
          processingTime: new Date().toISOString()
        };

        return { success: false, report: fallbackReport, business, error };
      }
    };

    // Process businesses in batches with concurrency limit
    for (let i = 0; i < businessList.length; i += CONCURRENCY_LIMIT) {
      const batch = businessList.slice(i, i + CONCURRENCY_LIMIT);
      console.log(`\n🚀 Processing batch ${Math.floor(i / CONCURRENCY_LIMIT) + 1}/${Math.ceil(businessList.length / CONCURRENCY_LIMIT)} (${batch.length} businesses in parallel)...`);

      const batchResults = await Promise.allSettled(
        batch.map((business, batchIndex) => processBusiness(business, i + batchIndex))
      );

      // Collect results
      batchResults.forEach((result) => {
        if (result.status === 'fulfilled' && result.value) {
          auditResults.push(result.value.report);
          creditsUsed++;

          if (result.value.error) {
            errors.push(result.value.error);
          }
        }
      });
    }

    if (auditResults.length === 0) {
      return res.status(500).json({
        error: 'Fast bulk scan failed - no businesses could be processed',
        errors: errors,
        details: 'All business scans failed. Check server logs for details.'
      });
    }

    console.log(`📊 Generating fast competitive analysis for ${auditResults.length} businesses...`);

    // Generate lightweight competitive analysis
    const competitiveAnalysis = generateCompetitiveAnalysis(auditResults, industry, location);
    const industryBenchmarks = calculateIndustryBenchmarks(auditResults);
    const opportunityMatrix = identifyOpportunities(auditResults);

    // Create fast bulk scan report
    const fastBulkReport = {
      success: true,
      type: 'fast_bulk_scan',
      searchCriteria: {
        industry: industry,
        location: location,
        totalScanned: auditResults.length,
        startingPosition: actualStartFrom,
        endingPosition: actualStartFrom + auditResults.length - 1
      },
      generatedDate: new Date().toLocaleDateString(),

      // Executive Summary
      executiveSummary: competitiveAnalysis.summary,

      // Individual Business Reports (fast version)
      businesses: auditResults,

      // Competitive Analysis
      competitiveAnalysis: competitiveAnalysis,

      // Industry Benchmarks
      industryBenchmarks: industryBenchmarks,

      // Opportunity Analysis
      opportunityMatrix: opportunityMatrix,

      // Fast scan metrics summary
      scanSummary: {
        averageScore: Math.round(auditResults.reduce((sum, r) => sum + r.score, 0) / auditResults.length),
        averageReviews: Math.round(auditResults.reduce((sum, r) => sum + r.coreMetrics.totalReviews, 0) / auditResults.length),
        averagePhotos: Math.round(auditResults.reduce((sum, r) => sum + r.coreMetrics.totalPhotos, 0) / auditResults.length),
        avgCitations: Math.round(auditResults.reduce((sum, r) => sum + r.coreMetrics.citationsFound, 0) / auditResults.length),
        businessesWithGBP: auditResults.filter(r => r.coreMetrics.hasGBPEmbed).length,
        businessesWithSocial: auditResults.filter(r => r.coreMetrics.socialLinks > 0).length
      },

      // Errors (if any)
      errors: errors,

      // Credits used
      creditsUsed: creditsUsed,

      // Performance info
      processedIn: 'fast_mode',
      skippedAnalysis: ['ai_suggestions', 'content_analysis', 'detailed_reviews']
    };

    // Save fast bulk scan report
    const reportDataStr = JSON.stringify(fastBulkReport);
    try {
      await db.query(
        'INSERT INTO reports (user_id, business_name, city, industry, website, report_data) VALUES ($1, $2, $3, $4, $5, $6)',
        [
          req.user.id,
          `Fast Bulk: ${industry}`,
          location,
          industry,
          null,
          reportDataStr
        ]
      );
      console.log(`💾 Fast bulk scan saved to database`);
    } catch (dbError) {
      console.error('Error saving fast bulk scan:', dbError);
    }

    // Deduct credits
    try {
      await db.query(
        'UPDATE users SET credits_remaining = credits_remaining - $1 WHERE id = $2',
        [creditsUsed, req.user.id]
      );
      console.log(`💳 ${creditsUsed} credits deducted for fast scan`);
    } catch (creditError) {
      console.error('Error updating credits:', creditError);
    }

    console.log(`\n⚡ Fast bulk scan complete! Analyzed ${auditResults.length} businesses in fast mode`);

    // Send email notification to user
    try {
      await sendBulkAuditCompleteEmail({
        userEmail: req.user.email,
        userName: req.user.firstName || req.user.email.split('@')[0],
        userId: req.user.id,
        industry: industry,
        location: location,
        businessesScanned: auditResults.length,
        averageScore: Math.round(auditResults.reduce((sum, r) => sum + r.score, 0) / auditResults.length),
        creditsUsed: creditsUsed,
        completedAt: new Date().toLocaleString()
      });
      console.log(`📧 Bulk audit completion email sent to ${req.user.email}`);
    } catch (emailError) {
      console.error('⚠️ Failed to send bulk audit completion email:', emailError);
      // Don't fail the request if email fails, just log it
    }

    res.json(fastBulkReport);

  } catch (error) {
    console.error('❌ Fast bulk scan error:', error);
    res.status(500).json({
      error: 'Fast bulk scan failed',
      details: error.message
    });
  }
});

// Competitive Analysis Around Target Business
app.post('/api/competitive-analysis-around-business', authenticateToken, async (req, res) => {
  try {
    const { businessName, location, industry } = req.body;

    // Validation
    if (!businessName || !location || !industry) {
      return res.status(400).json({ error: 'Business name, location, and industry are required' });
    }

    console.log(`🎯 Starting competitive analysis around: ${businessName} in ${location}`);

    // Step 1: Get business rankings to find target business's position
    const allBusinesses = await getBusinessRankings(industry, location, 100, 1);

    if (!allBusinesses || allBusinesses.length === 0) {
      return res.status(404).json({ error: 'No businesses found for this industry/location' });
    }

    // Step 2: Find the target business in the rankings
    const targetIndex = allBusinesses.findIndex(b =>
      b.name.toLowerCase().includes(businessName.toLowerCase()) ||
      businessName.toLowerCase().includes(b.name.toLowerCase())
    );

    if (targetIndex === -1) {
      return res.status(404).json({
        error: `Could not find "${businessName}" in the top 100 rankings for ${industry} in ${location}`,
        suggestion: 'Try using the exact business name as it appears on Google Maps'
      });
    }

    const targetRank = targetIndex + 1;
    console.log(`📍 Found target business at rank #${targetRank}`);

    // Step 3: Determine which businesses to analyze (5 above + target + 5 below)
    let startIndex, endIndex, businessesToScan;

    if (targetRank <= 5) {
      // If in top 5, scan from #1 to target + 5 below
      startIndex = 0;
      endIndex = Math.min(targetIndex + 5, allBusinesses.length - 1);
      console.log(`📊 Target is in top 5 - scanning ranks #1 to #${endIndex + 1}`);
    } else {
      // Otherwise, scan 5 above + target + 5 below
      startIndex = Math.max(0, targetIndex - 5);
      endIndex = Math.min(targetIndex + 5, allBusinesses.length - 1);
      console.log(`📊 Scanning ranks #${startIndex + 1} to #${endIndex + 1} (centered around #${targetRank})`);
    }

    businessesToScan = allBusinesses.slice(startIndex, endIndex + 1);
    const totalToScan = businessesToScan.length;

    // Step 4: Check if user has enough credits
    const creditsNeeded = totalToScan;
    if (req.user.credits_remaining < creditsNeeded) {
      return res.status(402).json({
        error: `Insufficient credits. This competitive analysis requires ${creditsNeeded} credits (analyzing ${totalToScan} businesses). You have ${req.user.credits_remaining}.`,
        creditsNeeded,
        creditsAvailable: req.user.credits_remaining
      });
    }

    console.log(`💳 User has ${req.user.credits_remaining} credits, needs ${creditsNeeded} for ${totalToScan} businesses`);

    // Step 5: Run fast audits on all businesses (3 at a time)
    const auditResults = [];
    const errors = [];
    let creditsUsed = 0;
    const CONCURRENCY_LIMIT = 3;

    const processBusiness = async (business, index) => {
      console.log(`\n⚡ Scanning ${index + 1}/${businessesToScan.length}: ${business.name} (Rank #${business.rank})`);

      try {
        const report = await generateFastBulkReport(
          business.name,
          business.location || location,
          industry,
          business.website
        );

        report.ranking = {
          position: business.rank,
          searchTerm: `${industry} ${location}`,
          url: business.website,
          isTarget: business.name.toLowerCase() === businessName.toLowerCase()
        };

        console.log(`✅ Scan complete: ${business.name} - Score: ${report.score}/${report.maxScore}`);
        return { success: true, report, business };

      } catch (businessError) {
        console.error(`❌ Scan failed for ${business.name}:`, businessError.message);

        const fallbackReport = {
          success: false,
          type: 'fast_bulk',
          businessName: business.name,
          location: location,
          industry: industry,
          website: business.website || null,
          ranking: {
            position: business.rank,
            searchTerm: `${industry} ${location}`,
            url: business.website,
            isTarget: business.name.toLowerCase() === businessName.toLowerCase()
          },
          score: 0,
          maxScore: 96,
          coreMetrics: {
            isClaimed: false,
            meetsClaimedReq: false,
            hasDescription: false,
            meetsDescriptionReq: false,
            categoriesCount: 0,
            meetsCategoriesReq: false,
            photosCount: 0,
            meetsPhotosReq: false,
            reviewsCount: 0,
            averageRating: 0,
            meetsReviewsReq: false,
            productTilesCount: 0,
            meetsProductTilesReq: false,
            postsCount: 0,
            meetsPostsReq: false,
            socialLinksCount: 0,
            meetsSocialReq: false,
            hasLocalLandingPage: false,
            meetsLocalLandingPageReq: false
          },
          errors: [businessError.message]
        };

        return { success: false, report: fallbackReport, business, error: businessError.message };
      }
    };

    // Process in batches
    for (let i = 0; i < businessesToScan.length; i += CONCURRENCY_LIMIT) {
      const batch = businessesToScan.slice(i, i + CONCURRENCY_LIMIT);
      console.log(`\n🚀 Processing batch ${Math.floor(i / CONCURRENCY_LIMIT) + 1}/${Math.ceil(businessesToScan.length / CONCURRENCY_LIMIT)}`);

      const batchResults = await Promise.allSettled(
        batch.map((business, batchIndex) => processBusiness(business, i + batchIndex))
      );

      batchResults.forEach((result) => {
        if (result.status === 'fulfilled' && result.value) {
          auditResults.push(result.value.report);
          creditsUsed++;
          if (result.value.error) {
            errors.push(result.value.error);
          }
        }
      });
    }

    if (auditResults.length === 0) {
      return res.status(500).json({
        error: 'Competitive analysis failed - no businesses could be processed',
        errors: errors
      });
    }

    console.log(`📊 Generating competitive analysis for ${auditResults.length} businesses...`);

    // Generate analysis
    const competitiveAnalysis = generateCompetitiveAnalysis(auditResults, industry, location);
    const industryBenchmarks = calculateIndustryBenchmarks(auditResults);
    const opportunityMatrix = identifyOpportunities(auditResults);

    // Find target business in results
    const targetBusiness = auditResults.find(r =>
      r.ranking && r.ranking.isTarget
    ) || auditResults.find(r =>
      r.businessName.toLowerCase() === businessName.toLowerCase()
    );

    // Create response
    const competitiveReport = {
      success: true,
      type: 'competitive_analysis_around_business',
      targetBusiness: {
        name: businessName,
        rank: targetRank,
        score: targetBusiness?.score || 0,
        maxScore: targetBusiness?.maxScore || 96
      },
      searchCriteria: {
        industry: industry,
        location: location,
        totalScanned: auditResults.length,
        startingPosition: startIndex + 1,
        endingPosition: endIndex + 1,
        targetPosition: targetRank
      },
      generatedDate: new Date().toLocaleDateString(),
      executiveSummary: competitiveAnalysis.summary,
      businesses: auditResults,
      competitiveAnalysis: competitiveAnalysis,
      industryBenchmarks: industryBenchmarks,
      opportunityMatrix: opportunityMatrix,
      scanSummary: {
        averageScore: Math.round(auditResults.reduce((sum, r) => sum + r.score, 0) / auditResults.length),
        averageReviews: Math.round(auditResults.reduce((sum, r) => sum + r.coreMetrics.totalReviews, 0) / auditResults.length),
        averagePhotos: Math.round(auditResults.reduce((sum, r) => sum + r.coreMetrics.totalPhotos, 0) / auditResults.length),
        businessesWithGBP: auditResults.filter(r => r.coreMetrics.hasGBPEmbed).length,
        businessesWithSocial: auditResults.filter(r => r.coreMetrics.socialLinks > 0).length
      },
      errors: errors.length > 0 ? errors : undefined,
      creditsUsed: creditsUsed
    };

    // Deduct credits
    try {
      await db.query(
        'UPDATE users SET credits_remaining = credits_remaining - $1 WHERE id = $2',
        [creditsUsed, req.user.id]
      );
      console.log(`💳 ${creditsUsed} credits deducted for competitive analysis`);
    } catch (creditError) {
      console.error('Error updating credits:', creditError);
    }

    console.log(`\n✅ Competitive analysis complete! Analyzed ${auditResults.length} businesses around ${businessName}`);

    res.json(competitiveReport);

  } catch (error) {
    console.error('❌ Competitive analysis error:', error);
    res.status(500).json({
      error: 'Competitive analysis failed',
      details: error.message
    });
  }
});

// Compare two businesses with AI analysis
app.post('/api/compare-businesses', authenticateToken, async (req, res) => {
  try {
    const { business1, business2 } = req.body;

    if (!business1 || !business2) {
      return res.status(400).json({ error: 'Both businesses are required for comparison' });
    }

    console.log(`🔍 Comparing: ${business1.name} (Rank #${business1.rank}) vs ${business2.name} (Rank #${business2.rank})`);

    // Determine which is higher/lower ranked
    const higherRanked = business1.rank < business2.rank ? business1 : business2;
    const lowerRanked = business1.rank < business2.rank ? business2 : business1;

    // Prepare comparison data for AI
    const comparisonPrompt = `You are an SEO expert analyzing two competing local businesses. Compare these two businesses and provide specific, actionable recommendations for the lower-ranked business to catch up.

HIGHER RANKED BUSINESS (#${higherRanked.rank}): ${higherRanked.name}
- Description: ${higherRanked.coreMetrics.meetsDescriptionReq ? '✅ Has 150+ char description' : '❌ Missing or short description'}
- Categories: ${higherRanked.coreMetrics.meetsCategoriesReq ? `✅ ${higherRanked.coreMetrics.categoriesCount} categories` : `❌ Only ${higherRanked.coreMetrics.categoriesCount} categories`}
- Photos: ${higherRanked.coreMetrics.meetsPhotosReq ? `✅ ${higherRanked.coreMetrics.photosCount} photos` : `❌ Only ${higherRanked.coreMetrics.photosCount} photos`}
- Reviews: ${higherRanked.coreMetrics.meetsReviewsReq ? `✅ ${higherRanked.coreMetrics.reviewsCount} reviews, ${higherRanked.coreMetrics.averageRating.toFixed(1)}⭐` : `❌ ${higherRanked.coreMetrics.reviewsCount} reviews, ${higherRanked.coreMetrics.averageRating.toFixed(1)}⭐`}
- Products/Services: ${higherRanked.coreMetrics.meetsProductTilesReq ? `✅ ${higherRanked.coreMetrics.productTilesCount} products` : `❌ ${higherRanked.coreMetrics.productTilesCount} products`}
- Posts: ${higherRanked.coreMetrics.meetsPostsReq ? '✅ Posted within 15 days' : '❌ No recent posts'}
- Social Links: ${higherRanked.coreMetrics.meetsSocialReq ? `✅ ${higherRanked.coreMetrics.socialLinksCount} platforms` : `❌ ${higherRanked.coreMetrics.socialLinksCount} platforms`}
- Local Landing Page: ${higherRanked.coreMetrics.meetsLocalLandingPageReq ? '✅ Has location-specific landing page' : '❌ No local landing page'}

LOWER RANKED BUSINESS (#${lowerRanked.rank}): ${lowerRanked.name}
- Description: ${lowerRanked.coreMetrics.meetsDescriptionReq ? '✅ Has 150+ char description' : '❌ Missing or short description'}
- Categories: ${lowerRanked.coreMetrics.meetsCategoriesReq ? `✅ ${lowerRanked.coreMetrics.categoriesCount} categories` : `❌ Only ${lowerRanked.coreMetrics.categoriesCount} categories`}
- Photos: ${lowerRanked.coreMetrics.meetsPhotosReq ? `✅ ${lowerRanked.coreMetrics.photosCount} photos` : `❌ Only ${lowerRanked.coreMetrics.photosCount} photos`}
- Reviews: ${lowerRanked.coreMetrics.meetsReviewsReq ? `✅ ${lowerRanked.coreMetrics.reviewsCount} reviews, ${lowerRanked.coreMetrics.averageRating.toFixed(1)}⭐` : `❌ ${lowerRanked.coreMetrics.reviewsCount} reviews, ${lowerRanked.coreMetrics.averageRating.toFixed(1)}⭐`}
- Products/Services: ${lowerRanked.coreMetrics.meetsProductTilesReq ? `✅ ${lowerRanked.coreMetrics.productTilesCount} products` : `❌ ${lowerRanked.coreMetrics.productTilesCount} products`}
- Posts: ${lowerRanked.coreMetrics.meetsPostsReq ? '✅ Posted within 15 days' : '❌ No recent posts'}
- Social Links: ${lowerRanked.coreMetrics.meetsSocialReq ? `✅ ${lowerRanked.coreMetrics.socialLinksCount} platforms` : `❌ ${lowerRanked.coreMetrics.socialLinksCount} platforms`}
- Local Landing Page: ${lowerRanked.coreMetrics.meetsLocalLandingPageReq ? '✅ Has location-specific landing page' : '❌ No local landing page'}

Provide:
1. A brief analysis (2-3 sentences) explaining WHY the higher-ranked business is ranking better
2. Specific, prioritized recommendations (3-5 action items) for the lower-ranked business to improve their ranking

Be concise and actionable.`;

    const aiResponse = await axios.post('https://api.openai.com/v1/chat/completions', {
      model: 'gpt-4o-mini',
      messages: [{
        role: 'user',
        content: comparisonPrompt
      }],
      max_tokens: 600,
      temperature: 0.7
    }, {
      headers: {
        'Authorization': `Bearer ${OPENAI_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    const analysisText = aiResponse.data.choices[0].message.content;

    // Split into analysis and recommendations
    const parts = analysisText.split(/(?:Recommendations|Action Items|To Improve):/i);
    const aiAnalysis = parts[0].trim();
    const recommendations = parts.length > 1 ? parts[1].trim() : analysisText;

    console.log(`✅ AI comparison generated successfully`);

    res.json({
      success: true,
      aiAnalysis: aiAnalysis,
      recommendations: recommendations,
      higherRanked: {
        name: higherRanked.name,
        rank: higherRanked.rank
      },
      lowerRanked: {
        name: lowerRanked.name,
        rank: lowerRanked.rank
      }
    });

  } catch (error) {
    console.error('❌ Comparison error:', error);
    res.status(500).json({
      error: 'Comparison failed',
      details: error.message
    });
  }
});

// Get user's reports history
app.get('/api/user-reports', authenticateToken, async (req, res) => {
  try {
    console.log(`📋 Loading reports for user ${req.user.id}`);
    
    // Try with was_paid column first, fallback if column doesn't exist
    let reports;
    try {
      reports = await db.all(
        'SELECT id, business_name, city, industry, website, created_at, report_data, was_paid FROM reports WHERE user_id = $1 ORDER BY created_at DESC',
        [req.user.id]
      );
    } catch (error) {
      if (error.message.includes('was_paid') && error.message.includes('does not exist')) {
        console.log('⚠️ was_paid column missing, using fallback query');
        reports = await db.all(
          'SELECT id, business_name, city, industry, website, created_at, report_data, FALSE as was_paid FROM reports WHERE user_id = $1 ORDER BY created_at DESC',
          [req.user.id]
        );
      } else {
        throw error;
      }
    }
    
    // Extract score from each report's JSON data
    const reportsWithScores = reports.map(report => {
      let score = null;
      try {
        if (report.report_data) {
          const reportData = JSON.parse(report.report_data);
          score = reportData.auditOverview?.overallScore?.score || reportData.finalScore || null;
        }
      } catch (parseError) {
        console.error(`Error parsing report data for report ${report.id}:`, parseError);
      }
      
      return {
        id: report.id,
        business_name: report.business_name,
        city: report.city,
        industry: report.industry,
        website: report.website,
        created_at: report.created_at,
        score: score,
        was_paid: report.was_paid
      };
    });
    
    console.log(`✅ Found ${reports.length} reports for user ${req.user.id}`);
    
    res.json({
      success: true,
      reports: reportsWithScores
    });
  } catch (error) {
    console.error('Error in user-reports endpoint:', error);
    res.status(500).json({ error: 'Failed to load reports' });
  }
});

// Unlock report endpoint - allows users to unlock specific locked reports
app.post('/api/reports/:id/unlock', authenticateToken, async (req, res) => {
  try {
    const reportId = req.params.id;
    console.log(`🔓 Unlock request for report ${reportId} from user ${req.user.id}`);
    
    // Check if user has credits
    if (req.user.credits_remaining <= 0) {
      return res.status(400).json({ 
        error: 'Insufficient credits. Please purchase credits to unlock this report.' 
      });
    }
    
    // Check if report exists and belongs to user
    const report = await db.get(
      'SELECT * FROM reports WHERE id = $1 AND user_id = $2',
      [reportId, req.user.id]
    );
    
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }
    
    // Check if report is already unlocked (handle missing was_paid column)
    const wasPaid = report.was_paid !== undefined ? report.was_paid : false;
    if (wasPaid) {
      return res.status(400).json({ 
        error: 'This report is already unlocked' 
      });
    }
    
    // Atomic credit deduction and report unlock
    try {
      // Deduct credit
      const creditResult = await db.query(
        'UPDATE users SET credits_remaining = credits_remaining - 1 WHERE id = $1 AND credits_remaining > 0 RETURNING credits_remaining',
        [req.user.id]
      );
      
      if (!creditResult.rows || creditResult.rows.length === 0) {
        return res.status(400).json({ 
          error: 'Failed to deduct credit. You may have run out of credits.' 
        });
      }
      
      // Unlock the report (handle missing was_paid column)
      try {
        await db.query(
          'UPDATE reports SET was_paid = $1 WHERE id = $2',
          [true, reportId]
        );
      } catch (error) {
        if (error.message.includes('was_paid') && error.message.includes('does not exist')) {
          console.log('⚠️ was_paid column missing, skipping report unlock flag');
          // Continue without updating was_paid - report will still be accessible via credits
        } else {
          throw error;
        }
      }
      
      const remainingCredits = creditResult.rows[0].credits_remaining;
      console.log(`🔓 Report ${reportId} unlocked! User now has ${remainingCredits} credits remaining`);
      
      // Return the unlocked report data
      const reportData = JSON.parse(report.report_data);
      const unlockedReport = {
        ...reportData,
        isLocked: false,
        optimizationOpportunities: 0
      };
      
      res.json({
        success: true,
        message: 'Report unlocked successfully!',
        report: unlockedReport,
        creditsRemaining: remainingCredits
      });
      
    } catch (dbError) {
      console.error('Database error during unlock:', dbError);
      return res.status(500).json({ 
        error: 'Failed to unlock report. Please try again.' 
      });
    }
    
  } catch (error) {
    console.error('Error in unlock report endpoint:', error);
    res.status(500).json({ error: 'Failed to unlock report' });
  }
});

// Detailed Citation Analysis endpoint
app.post('/api/detailed-citation-analysis', authenticateToken, async (req, res) => {
  try {
    const { businessName, phoneNumber, reportId } = req.body;
    
    console.log(`🔍 Detailed citation analysis request received`);
    console.log(`🔍 Request body:`, req.body);
    
    if (!businessName) {
      console.error('❌ Missing required fields:', { businessName, phoneNumber });
      return res.status(400).json({ error: 'Business name is required' });
    }
    
    // Check for SERPAPI key
    if (!SERPAPI_KEY) {
      console.error('❌ SERPAPI_KEY not configured');
      return res.status(500).json({ error: 'Citation analysis service not configured. Please contact support.' });
    }

    console.log(`🔍 Starting detailed citation analysis for: ${businessName} with phone: ${phoneNumber || 'none'}`);
    
    // Generate phone patterns for flexible matching
    const phonePatterns = generatePhoneSearchPatterns(phoneNumber);
    if (phonePatterns.length === 0 && phoneNumber) {
      console.warn('⚠️ No valid phone patterns generated from provided number');
    }
    console.log(`🔍 Generated ${phonePatterns.length} phone search patterns`);

    // Define 40 premium directories grouped into sets of 4
    const premiumDirectories = [
      // Group 1: General Business Directories
      [
        { name: 'About.me', domain: 'about.me' },
        { name: 'AmericanTowns', domain: 'americantowns.com' },
        { name: 'BizHWY', domain: 'bizhwy.com' },
        { name: 'Brownbook', domain: 'brownbook.net' }
      ],
      // Group 2: Local/City Directories
      [
        { name: 'City-Data', domain: 'city-data.com' },
        { name: 'CitySquares', domain: 'citysquares.com' },
        { name: 'Cybo', domain: 'cybo.com' },
        { name: 'Cylex', domain: 'cylex.us.com' }
      ],
      // Group 3: Business Search Directories
      [
        { name: 'EZLocal', domain: 'ezlocal.com' },
        { name: 'FindUsLocal', domain: 'finduslocal.com' },
        { name: 'Fyple', domain: 'fyple.com' },
        { name: 'Geebo', domain: 'geebo.com' }
      ],
      // Group 4: Local Search Platforms
      [
        { name: 'GoLocal247', domain: 'golocal247.com' },
        { name: 'Hotfrog', domain: 'hotfrog.com' },
        { name: 'InfoUSA', domain: 'infousa.com' },
        { name: 'Kompass US', domain: 'us.kompass.com' }
      ],
      // Group 5: Professional/Industry Directories
      [
        { name: 'Lexology', domain: 'lexology.com' },
        { name: 'Local.com', domain: 'local.com' },
        { name: 'LocalEdge', domain: 'localedge.com' },
        { name: 'Manta', domain: 'manta.com' }
      ],
      // Group 6: Business Network Directories
      [
        { name: 'MerchantCircle', domain: 'merchantcircle.com' },
        { name: 'MyHuckleberry', domain: 'myhuckleberry.com' },
        { name: 'n49', domain: 'n49.com' },
        { name: 'OpenStreetMap', domain: 'openstreetmap.org' }
      ],
      // Group 7: Content & Social Platforms
      [
        { name: 'Blogger', domain: 'blogger.com' },
        { name: 'Flipboard', domain: 'flipboard.com' },
        { name: 'Issuu', domain: 'issuu.com' },
        { name: 'Patch', domain: 'patch.com' }
      ],
      // Group 8: Social & Review Platforms
      [
        { name: 'Pinterest', domain: 'pinterest.com' },
        { name: 'Quora', domain: 'quora.com' },
        { name: 'Sitejabber', domain: 'sitejabber.com' },
        { name: 'Storeboard', domain: 'storeboard.com' }
      ],
      // Group 9: Professional & Industry Specific
      [
        { name: 'TED', domain: 'ted.com' },
        { name: 'ThreeBestRated', domain: 'threebestrated.com' },
        { name: 'Thomasnet', domain: 'thomasnet.com' },
        { name: 'Thumbtack', domain: 'thumbtack.com' }
      ],
      // Group 10: Yellow Pages & Local Search
      [
        { name: 'Yalwa', domain: 'yalwa.com' },
        { name: 'Yellow.place', domain: 'yellow.place' },
        { name: 'YellowPageCity', domain: 'yellowpagecity.com' },
        { name: 'ZeeMaps', domain: 'zeemaps.com' }
      ]
    ];

    const results = [];

    // Process each group of 4 directories
    console.log(`📊 Processing ${premiumDirectories.length} groups of directories...`);
    
    for (let groupIndex = 0; groupIndex < premiumDirectories.length; groupIndex++) {
      const group = premiumDirectories[groupIndex];
      try {
        // Create OR query for the group of 4 directories
        const siteQueries = group.map(dir => `site:${dir.domain}`).join(' OR ');
        
        // Create search query with phone number if available
        let searchQuery;
        if (phonePatterns.length > 0) {
          const primaryPhone = phonePatterns[0]; // Use most common format
          searchQuery = `(${siteQueries}) "${businessName}" "${primaryPhone}"`;
        } else {
          searchQuery = `(${siteQueries}) "${businessName}"`;
        }
        
        console.log(`🔍 Group ${groupIndex + 1}/10: Searching ${group.map(d => d.name).join(', ')}`);
        console.log(`🔍 Search query: ${searchQuery}`);

        const response = await axios.get('https://serpapi.com/search.json', {
          params: {
            engine: 'google',
            q: searchQuery,
            api_key: SERPAPI_KEY,
            num: 10, // More results to catch all 4 potential directories
            google_domain: 'google.com',
            gl: 'us',
            hl: 'en'
          },
          timeout: 10000
        });

        // Process results for each directory in the group with enhanced validation
        group.forEach(directory => {
          let found = false;
          let matchType = 'none';
          
          if (response.data.organic_results) {
            for (const result of response.data.organic_results) {
              if (result.link && result.link.includes(directory.domain)) {
                const resultText = `${result.title || ''} ${result.snippet || ''}`.toLowerCase();
                const businessNameFound = resultText.includes(businessName.toLowerCase());
                
                // Check if any phone pattern matches the result text
                let phoneFound = false;
                if (phonePatterns.length > 0) {
                  phoneFound = phonePatterns.some(pattern => 
                    resultText.includes(pattern.toLowerCase()) ||
                    resultText.includes(normalizePhoneNumber(pattern))
                  );
                } else {
                  // If no phone provided, just check business name
                  phoneFound = true;
                }
                
                if (businessNameFound && phoneFound) {
                  found = true;
                  matchType = phonePatterns.length > 0 ? 'name+phone' : 'name-only';
                  break;
                } else if (businessNameFound) {
                  // Business name found but no phone match
                  found = true;
                  matchType = 'name-only';
                  break;
                }
              }
            }
          }

          results.push({
            name: directory.name,
            domain: directory.domain,
            found: found,
            status: found ? 'FOUND' : 'MISSING',
            matchType: matchType
          });
        });

        // Rate limiting delay
        await new Promise(resolve => setTimeout(resolve, 500));
        
      } catch (groupError) {
        console.error(`❌ Group ${groupIndex + 1} search failed:`, groupError.message);
        console.error(`❌ Error details:`, groupError.response?.data || groupError);
        
        // Mark all directories in this group as error
        group.forEach(directory => {
          results.push({
            name: directory.name,
            domain: directory.domain,
            found: false,
            status: 'ERROR',
            error: groupError.message
          });
        });
      }
    }

    // Calculate summary stats
    const foundCount = results.filter(r => r.found).length;
    const totalScore = foundCount; // Simple 1 point per directory for premium
    
    const summary = {
      totalDirectories: 40,
      found: foundCount,
      missing: 40 - foundCount,
      percentage: Math.round((foundCount / 40) * 100),
      score: totalScore
    };

    console.log(`✅ Detailed citation analysis complete: ${foundCount}/40 directories found`);

    // Save analysis results to database if reportId is provided
    if (reportId) {
      try {
        const analysisData = {
          summary,
          results,
          timestamp: new Date().toISOString()
        };
        
        await db.query(
          'UPDATE reports SET detailed_citation_analysis = $1 WHERE id = $2 AND user_id = $3',
          [JSON.stringify(analysisData), reportId, req.user.id]
        );
        
        console.log(`💾 Detailed citation analysis saved to report ${reportId}`);
      } catch (dbError) {
        console.error('❌ Failed to save detailed citation analysis:', dbError);
        // Continue with response even if saving fails
      }
    }

    res.json({
      success: true,
      summary,
      results
    });

  } catch (error) {
    console.error('❌ Detailed citation analysis error:', error);
    res.status(500).json({ error: 'Failed to complete detailed citation analysis' });
  }
});

// Get a specific report by ID
app.get('/api/reports/:id', authenticateToken, async (req, res) => {
  try {
    const reportId = req.params.id;
    console.log(`📊 Loading report ${reportId} for user ${req.user.id}`);
    
    const report = await db.get(
      'SELECT * FROM reports WHERE id = $1 AND user_id = $2',
      [reportId, req.user.id]
    );
    
    if (!report) {
      console.log(`❌ Report ${reportId} not found for user ${req.user.id}`);
      return res.status(404).json({ error: 'Report not found' });
    }
    
    try {
      // Parse the stored JSON report data
      const reportData = JSON.parse(report.report_data);
      
      // Check if this report was originally paid for (handle missing was_paid column)
      const wasPaid = report.was_paid !== undefined ? report.was_paid : false;

      // Calculate optimization opportunities if the report is locked
      let optimizationOpportunities = 0;

      // Check if this is a bulk audit report (different structure)
      const isBulkReport = reportData.type === 'fast_bulk_scan';

      if (!wasPaid && !isBulkReport && reportData.auditOverview && reportData.auditOverview.factors) {
        // Regular audit reports
        optimizationOpportunities = reportData.auditOverview.factors.filter(factor =>
          factor.status === 'MISSING' || factor.status === 'NEEDS IMPROVEMENT'
        ).length;
      } else if (!wasPaid && isBulkReport && reportData.opportunityMatrix) {
        // Bulk audit reports - count high opportunity businesses
        optimizationOpportunities = reportData.opportunityMatrix.highOpportunity?.length || 0;
      }

      // Bulk reports are always "paid" (they cost credits to run)
      // Only lock regular single-business audits that weren't paid for
      const shouldLock = !isBulkReport && !wasPaid;

      // Add locked status based on original payment, not current credits
      const responseReport = {
        ...reportData,
        isLocked: shouldLock,
        optimizationOpportunities: shouldLock ? optimizationOpportunities : 0
      };
      
      // Include stored detailed citation analysis if it exists
      if (report.detailed_citation_analysis) {
        try {
          responseReport.detailedCitationAnalysis = JSON.parse(report.detailed_citation_analysis);
          console.log(`📊 Loaded stored detailed citation analysis for report ${reportId}`);
        } catch (analysisParseError) {
          console.error('❌ Failed to parse stored detailed citation analysis:', analysisParseError);
        }
      }

      // Fetch and apply factor overrides for this report (only for regular reports, not bulk)
      if (!isBulkReport && responseReport.auditOverview && responseReport.auditOverview.factors) {
        try {
          const overrides = await db.all(
            'SELECT factor_name, override_status FROM factor_overrides WHERE report_id = $1',
            [reportId]
          );

          if (overrides && overrides.length > 0) {
            console.log(`🔧 Applying ${overrides.length} factor override(s) to report ${reportId}`);

            // Create a map of overrides for quick lookup
            const overrideMap = {};
            overrides.forEach(override => {
              overrideMap[override.factor_name] = override.override_status;
            });

            // Apply overrides to factors
            responseReport.auditOverview.factors = responseReport.auditOverview.factors.map(factor => {
              if (overrideMap[factor.id]) {
                const newStatus = overrideMap[factor.id].toUpperCase().replace('_', ' ');
                console.log(`  ✏️ Override: ${factor.id} from ${factor.status} to ${newStatus}`);
                return {
                  ...factor,
                  status: newStatus,
                  manuallyOverridden: true
                };
              }
              return factor;
            });

            // Recalculate score based on overridden factors
            const totalFactors = responseReport.auditOverview.factors.length;
            const goodFactors = responseReport.auditOverview.factors.filter(f => f.status === 'GOOD').length;
            const needsImprovementFactors = responseReport.auditOverview.factors.filter(f => f.status === 'NEEDS IMPROVEMENT').length;
            const missingFactors = responseReport.auditOverview.factors.filter(f => f.status === 'MISSING').length;

            // Score calculation: GOOD = 100%, NEEDS IMPROVEMENT = 50%, MISSING = 0%
            const newScore = Math.round(((goodFactors * 100) + (needsImprovementFactors * 50)) / totalFactors);

            console.log(`  📊 Recalculated score: ${newScore} (was: ${responseReport.auditOverview.overallScore?.score || 'unknown'})`);
            console.log(`     Good: ${goodFactors}, Needs Improvement: ${needsImprovementFactors}, Missing: ${missingFactors}`);

            // Update the score
            if (!responseReport.auditOverview.overallScore) {
              responseReport.auditOverview.overallScore = {};
            }
            responseReport.auditOverview.overallScore.score = newScore;
            responseReport.finalScore = newScore;

            // Update optimization opportunities count
            optimizationOpportunities = missingFactors + needsImprovementFactors;
            if (shouldLock) {
              responseReport.optimizationOpportunities = optimizationOpportunities;
            }
          }
        } catch (overrideError) {
          console.error('❌ Error fetching/applying factor overrides:', overrideError);
          // Continue without overrides if there's an error
        }
      }

      const reportType = isBulkReport ? 'BULK AUDIT' : (wasPaid ? 'PAID' : 'LOCKED');
      console.log(`✅ Successfully loaded report ${reportId} (${reportType})`);

      res.json({
        success: true,
        report: responseReport
      });
    } catch (parseError) {
      console.error('Error parsing report data:', parseError);
      return res.status(500).json({ error: 'Report data is corrupted' });
    }
  } catch (error) {
    console.error('Error in report retrieval endpoint:', error);
    res.status(500).json({ error: 'Failed to load report' });
  }
});

// Test webhook endpoints (for testing only)
app.post('/api/test/email-verification', authenticateToken, async (req, res) => {
  try {
    const { email, firstName } = req.body;
    
    if (!email || !firstName) {
      return res.status(400).json({ error: 'Email and firstName are required' });
    }
    
    // Generate a test token
    const testToken = 'test-verification-token-' + Date.now();
    
    console.log('📧 TEST: Sending email verification webhook');
    
    // Send the email verification
    await sendVerificationEmail(email, firstName, testToken);
    
    res.json({
      success: true,
      message: 'Test email verification sent',
      testData: {
        email,
        firstName,
        token: testToken,
        webhookUrl: process.env.EMAIL_VERIFICATION_WEBHOOK_URL || process.env.EMAIL_WEBHOOK_URL || process.env.FEEDBACK_WEBHOOK_URL || 'NO WEBHOOK URL CONFIGURED'
      }
    });
  } catch (error) {
    console.error('Test email verification error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/test/password-reset', authenticateToken, async (req, res) => {
  try {
    const { email, firstName } = req.body;
    
    if (!email || !firstName) {
      return res.status(400).json({ error: 'Email and firstName are required' });
    }
    
    // Generate a test token
    const testToken = 'test-reset-token-' + Date.now();
    
    console.log('📧 TEST: Sending password reset webhook');
    
    // Send the password reset email
    await sendPasswordResetEmail(email, firstName, testToken);
    
    res.json({
      success: true,
      message: 'Test password reset sent',
      testData: {
        email,
        firstName,
        token: testToken,
        webhookUrl: process.env.PASSWORD_RESET_WEBHOOK_URL || process.env.EMAIL_WEBHOOK_URL || process.env.FEEDBACK_WEBHOOK_URL || 'NO WEBHOOK URL CONFIGURED'
      }
    });
  } catch (error) {
    console.error('Test password reset error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/test/feedback', authenticateToken, async (req, res) => {
  try {
    const { rating, message, type = 'general' } = req.body;
    
    if (!rating || !message) {
      return res.status(400).json({ error: 'Rating and message are required' });
    }
    
    console.log('📧 TEST: Sending feedback webhook');
    
    // Send the feedback email
    await sendFeedbackEmail({
      rating,
      type,
      message,
      email: req.user.email,
      reportData: {
        businessName: 'Test Business',
        location: 'Test Location',
        industry: 'Test Industry'
      },
      userId: req.user.id,
      userName: req.user.firstName || 'Test User'
    });
    
    res.json({
      success: true,
      message: 'Test feedback sent',
      testData: {
        rating,
        message,
        type,
        webhookUrl: process.env.FEEDBACK_WEBHOOK_URL || 'NO WEBHOOK URL CONFIGURED'
      }
    });
  } catch (error) {
    console.error('Test feedback error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/test/new-user', authenticateToken, async (req, res) => {
  try {
    const { email, firstName, lastName } = req.body;

    if (!email || !firstName || !lastName) {
      return res.status(400).json({ error: 'Email, firstName, and lastName are required' });
    }

    console.log('📧 TEST: Sending new user webhook');

    // Send the new user notification
    await sendNewUserNotification({
      userId: 'test-user-' + Date.now(),
      email,
      firstName,
      lastName,
      signupDate: new Date().toISOString(),
      plan: 'test',
      initialCredits: 0
    });

    res.json({
      success: true,
      message: 'Test new user alert sent',
      testData: {
        email,
        firstName,
        lastName,
        webhookUrl: process.env.NEW_USER_WEBHOOK_URL || process.env.FEEDBACK_WEBHOOK_URL || 'NO WEBHOOK URL CONFIGURED'
      }
    });
  } catch (error) {
    console.error('Test new user error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/test/bulk-audit-complete', authenticateToken, async (req, res) => {
  try {
    const { industry, location, businessesScanned = 10 } = req.body;

    if (!industry || !location) {
      return res.status(400).json({ error: 'Industry and location are required' });
    }

    console.log('📧 TEST: Sending bulk audit completion webhook');

    // Send the bulk audit completion email
    await sendBulkAuditCompleteEmail({
      userEmail: req.user.email,
      userName: req.user.firstName || req.user.email.split('@')[0],
      userId: req.user.id,
      industry,
      location,
      businessesScanned,
      averageScore: 67,
      creditsUsed: businessesScanned,
      completedAt: new Date().toLocaleString()
    });

    res.json({
      success: true,
      message: 'Test bulk audit completion email sent',
      testData: {
        userEmail: req.user.email,
        industry,
        location,
        businessesScanned,
        webhookUrl: process.env.BULK_AUDIT_WEBHOOK_URL || process.env.EMAIL_WEBHOOK_URL || process.env.FEEDBACK_WEBHOOK_URL || 'NO WEBHOOK URL CONFIGURED'
      }
    });
  } catch (error) {
    console.error('Test bulk audit email error:', error);
    res.status(500).json({ error: error.message });
  }
});

// API status endpoint
app.get('/api/status', (req, res) => {
  res.json({
    server: 'Local SEO Audit v3',
    status: 'running',
    timestamp: new Date().toISOString(),
    apis: {
      outscraper: !!OUTSCRAPER_API_KEY ? 'configured' : 'missing',
      scrapingbee: !!SCRAPINGBEE_API_KEY ? 'configured' : 'missing',
      openai: !!OPENAI_API_KEY ? 'configured' : 'missing',
      serpapi: !!SERPAPI_KEY ? 'configured' : 'missing'
    },
    database: 'connected',
    version: '3.0.0'
  });
});

// ==========================================
// FEEDBACK API ENDPOINT
// ==========================================

app.post('/api/feedback', authenticateToken, async (req, res) => {
  try {
    const { rating, type, message, email, reportData } = req.body;
    const userId = req.user.id;
    
    // Validate required fields
    if (!rating || !type || !message) {
      return res.status(400).json({ error: 'Rating, type, and message are required' });
    }
    
    // Validate rating range
    if (rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Rating must be between 1 and 5' });
    }
    
    // Validate feedback type
    const validTypes = ['general', 'bug', 'feature', 'performance'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: 'Invalid feedback type' });
    }
    
    console.log(`💬 Feedback received: ${rating} stars, Type: ${type}, User: ${userId}`);
    
    try {
      // Insert feedback into database - Fixed column names to match schema
      const result = await db.query(`
        INSERT INTO feedback (user_id, rating, feedback_type, message, user_email, report_data)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
      `, [
        userId,
        rating,
        type,
        message,
        email || null,
        reportData ? JSON.stringify(reportData) : null
      ]);
      
      const feedbackId = result.rows[0].id;
      console.log(`✅ Feedback saved successfully for user ${userId} with ID: ${feedbackId}`);
      
      // Send email notification
      try {
        await sendFeedbackEmail({
          rating,
          type,
          message,
          email,
          reportData,
          userId,
          userName: req.user.firstName || 'Unknown User'
        });
        console.log(`📧 Feedback email sent successfully`);
      } catch (emailError) {
        console.error('⚠️ Failed to send feedback email:', emailError);
        // Don't fail the request if email fails, just log it
      }
      
      res.json({ 
        success: true, 
        message: 'Feedback submitted successfully. Thank you for your input!' 
      });
    } catch (error) {
      console.error('❌ Database error:', error);
      return res.status(500).json({ error: 'Failed to save feedback. Please try again.' });
    }
    
  } catch (error) {
    console.error('❌ Feedback submission error:', error);
    res.status(500).json({ 
      error: 'Failed to submit feedback. Please try again.' 
    });
  }
});

// ==========================================
// FACTOR OVERRIDE API ENDPOINTS
// ==========================================

// Save or update a factor override
app.post('/api/factor-override', authenticateToken, async (req, res) => {
  try {
    const { reportId, factorName, overrideStatus, aiDetectedStatus, businessName } = req.body;
    const userId = req.user.id;

    // Validate required fields
    if (!reportId || !factorName || !overrideStatus) {
      return res.status(400).json({ error: 'Report ID, factor name, and override status are required' });
    }

    // Validate override status
    const validStatuses = ['missing', 'needs_improvement', 'good'];
    if (!validStatuses.includes(overrideStatus)) {
      return res.status(400).json({ error: 'Invalid override status. Must be: missing, needs_improvement, or good' });
    }

    console.log(`🔧 Factor override: Report ${reportId}, Factor: ${factorName}, Status: ${overrideStatus}`);

    try {
      // Insert or update override (UPSERT)
      const result = await db.query(`
        INSERT INTO factor_overrides (report_id, user_id, business_name, factor_name, override_status, ai_detected_status, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (report_id, factor_name)
        DO UPDATE SET
          override_status = $5,
          ai_detected_status = $6,
          updated_at = NOW()
        RETURNING id, created_at, updated_at
      `, [reportId, userId, businessName || '', factorName, overrideStatus, aiDetectedStatus || null]);

      const override = result.rows[0];
      console.log(`✅ Factor override saved for report ${reportId}, factor: ${factorName}`);

      res.json({
        success: true,
        message: 'Factor status updated successfully',
        override: {
          id: override.id,
          reportId,
          factorName,
          overrideStatus,
          createdAt: override.created_at,
          updatedAt: override.updated_at
        }
      });
    } catch (dbError) {
      console.error('❌ Database error saving factor override:', dbError);
      return res.status(500).json({ error: 'Failed to save factor override. Please try again.' });
    }

  } catch (error) {
    console.error('❌ Factor override error:', error);
    res.status(500).json({
      error: 'Failed to update factor status. Please try again.'
    });
  }
});

// Get all factor overrides for a report
app.get('/api/factor-overrides/:reportId', authenticateToken, async (req, res) => {
  try {
    const { reportId } = req.params;
    const userId = req.user.id;

    if (!reportId) {
      return res.status(400).json({ error: 'Report ID is required' });
    }

    try {
      // Fetch all overrides for this report
      const result = await db.query(`
        SELECT
          id,
          report_id,
          factor_name,
          override_status,
          ai_detected_status,
          created_at,
          updated_at
        FROM factor_overrides
        WHERE report_id = $1 AND user_id = $2
        ORDER BY updated_at DESC
      `, [reportId, userId]);

      const overrides = result.rows.reduce((acc, row) => {
        acc[row.factor_name] = {
          id: row.id,
          overrideStatus: row.override_status,
          aiDetectedStatus: row.ai_detected_status,
          createdAt: row.created_at,
          updatedAt: row.updated_at
        };
        return acc;
      }, {});

      console.log(`📋 Retrieved ${result.rows.length} factor overrides for report ${reportId}`);

      res.json({
        success: true,
        reportId: parseInt(reportId),
        overrides
      });
    } catch (dbError) {
      console.error('❌ Database error fetching factor overrides:', dbError);
      return res.status(500).json({ error: 'Failed to fetch factor overrides. Please try again.' });
    }

  } catch (error) {
    console.error('❌ Factor overrides fetch error:', error);
    res.status(500).json({
      error: 'Failed to fetch factor overrides. Please try again.'
    });
  }
});

// ==========================================
// CITATION BUILDING SERVICE ENDPOINT
// ==========================================

// Create Stripe checkout session for citation building service
app.post('/api/create-citation-checkout', authenticateToken, async (req, res) => {
  try {
    const { packageSize, businessName, address, phone, citationPriorities } = req.body;
    const userId = req.user.id;

    // Validate package size
    if (![25, 50].includes(packageSize)) {
      return res.status(400).json({ error: 'Invalid package size. Must be 25 or 50.' });
    }

    // Validate required fields
    if (!businessName || !address || !phone) {
      return res.status(400).json({ error: 'Business name, address, and phone are required.' });
    }

    // Define pricing (in cents)
    const pricing = {
      25: 3000, // $30.00
      50: 5000  // $50.00
    };

    console.log(`📋 Creating citation checkout: ${packageSize} citations for ${businessName}`);

    if (citationPriorities) {
      console.log(`  📊 Citation priorities: ${citationPriorities.missingCount || 0} missing, ${citationPriorities.foundCount || 0} found`);
      if (citationPriorities.missing && citationPriorities.missing.length > 0) {
        console.log(`  🎯 Priority directories (missing/red):`, citationPriorities.missing.map(c => c.directory).join(', '));
      }
    }

    // Prepare metadata with citation priorities
    const metadata = {
      user_id: userId.toString(),
      service_type: 'citation_building',
      package_size: packageSize.toString(),
      business_name: businessName,
      business_address: address,
      business_phone: phone
    };

    // Add citation priority data if available
    if (citationPriorities) {
      metadata.missing_count = (citationPriorities.missingCount || 0).toString();
      metadata.found_count = (citationPriorities.foundCount || 0).toString();
      metadata.total_analyzed = (citationPriorities.totalAnalyzed || 0).toString();

      // Store missing citations list (prioritize these first)
      if (citationPriorities.missing && citationPriorities.missing.length > 0) {
        metadata.priority_citations = JSON.stringify(citationPriorities.missing.slice(0, 30)); // Stripe has metadata limits
      }

      // Store found citations list
      if (citationPriorities.found && citationPriorities.found.length > 0) {
        metadata.existing_citations = JSON.stringify(citationPriorities.found.slice(0, 30));
      }
    }

    // Create Stripe checkout session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: `Citation Building Service - ${packageSize} Citations`,
              description: citationPriorities && citationPriorities.missingCount > 0
                ? `Build ${packageSize} citations (prioritizing ${citationPriorities.missingCount} missing directories)`
                : `Build your business presence across ${packageSize} local directories`,
              metadata: {
                service_type: 'citation_building',
                package_size: packageSize.toString()
              }
            },
            unit_amount: pricing[packageSize],
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      success_url: `${process.env.APP_URL || 'http://localhost:3000'}?citation_success=true`,
      cancel_url: `${process.env.APP_URL || 'http://localhost:3000'}?citation_cancelled=true`,
      metadata: metadata,
      customer_email: req.user.email
    });

    console.log(`✅ Citation checkout session created: ${session.id}`);

    res.json({
      success: true,
      url: session.url,
      sessionId: session.id
    });

  } catch (error) {
    console.error('❌ Citation checkout error:', error);
    res.status(500).json({
      error: 'Failed to create checkout session. Please try again.'
    });
  }
});

// ==========================================
// ADMIN ENDPOINTS
// ==========================================

// Get all users (admin endpoint - protect this in production!)
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin (you should implement proper admin authentication)
    // For now, only allow specific email
    if (req.user.email !== 'trylocality@gmail.com') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const users = await db.all(`
      SELECT 
        id, 
        email, 
        first_name, 
        last_name, 
        credits_remaining, 
        subscription_tier,
        created_at,
        updated_at,
        (SELECT COUNT(*) FROM reports WHERE user_id = users.id) as report_count
      FROM users 
      ORDER BY created_at DESC
    `);
    
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Export users to CSV
app.get('/api/admin/users/export', async (req, res) => {
  try {
    // Handle token from query params for CSV download
    const token = req.query.token || (req.headers['authorization'] && req.headers['authorization'].split(' ')[1]);
    
    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }
    
    let user;
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      user = await db.get('SELECT * FROM users WHERE id = $1', [decoded.userId]);
    } catch (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    // Check if user is admin
    if (!user || user.email !== 'trylocality@gmail.com') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const users = await db.all(`
      SELECT 
        id, 
        email, 
        first_name, 
        last_name, 
        credits_remaining, 
        subscription_tier,
        created_at,
        (SELECT COUNT(*) FROM reports WHERE user_id = users.id) as report_count
      FROM users 
      ORDER BY created_at DESC
    `);
    
    // Create CSV content
    const csvHeader = 'ID,Email,First Name,Last Name,Credits,Subscription,Reports Generated,Joined Date\n';
    const csvRows = users.map(user => {
      const joinedDate = new Date(user.created_at).toLocaleDateString();
      return `${user.id},"${user.email}","${user.first_name}","${user.last_name}",${user.credits_remaining},"${user.subscription_tier}",${user.report_count},"${joinedDate}"`;
    }).join('\n');
    
    const csvContent = csvHeader + csvRows;
    
    // Send as downloadable CSV file
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="users-export.csv"');
    res.send(csvContent);
    
  } catch (error) {
    console.error('Error exporting users:', error);
    res.status(500).json({ error: 'Failed to export users' });
  }
});

// Get user analytics
app.get('/api/admin/analytics', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.email !== 'trylocality@gmail.com') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const stats = await db.get(`
      SELECT 
        COUNT(DISTINCT users.id) as total_users,
        COUNT(DISTINCT CASE WHEN users.subscription_tier != 'free' THEN users.id END) as paid_users,
        COUNT(DISTINCT reports.id) as total_reports,
        SUM(CASE WHEN users.created_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) as new_users_week,
        SUM(CASE WHEN users.created_at >= datetime('now', '-30 days') THEN 1 ELSE 0 END) as new_users_month
      FROM users
      LEFT JOIN reports ON users.id = reports.user_id
    `);
    
    res.json(stats);
  } catch (error) {
    console.error('Error fetching analytics:', error);
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// ==========================================
// ERROR HANDLING & STARTUP
// ==========================================

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// ==========================================
// STRIPE CHECKOUT ENDPOINTS
// ==========================================

// Create Stripe checkout session
app.post('/api/create-checkout-session', authenticateToken, async (req, res) => {
  try {
    const { priceType } = req.body;
    console.log(`🛒 Checkout session request - priceType: "${priceType}", type: ${typeof priceType}`);
    console.log(`🛒 Available price types:`, Object.keys(STRIPE_PRICES));
    console.log(`🛒 Full request body:`, req.body);
    
    if (!['oneTime', 'pro', 'premium'].includes(priceType)) {
      console.log(`❌ Invalid price type "${priceType}" - not in allowed list`);
      return res.status(400).json({ error: 'Invalid price type' });
    }
    
    const priceId = STRIPE_PRICES[priceType];
    const credits = CREDIT_AMOUNTS[priceType];
    
    // Create line items based on price type
    const lineItems = [{
      price: priceId,
      quantity: 1
    }];
    
    // Create checkout session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: lineItems,
      mode: priceType === 'oneTime' ? 'payment' : 'subscription',
      success_url: `${req.protocol}://${req.get('host')}/?payment=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.protocol}://${req.get('host')}/pricing.html?payment=cancelled`,
      customer_email: req.user.email,
      metadata: {
        userId: req.user.id.toString(),
        priceType: priceType,
        credits: credits.toString()
      },
      allow_promotion_codes: true
    });
    
    res.json({ url: session.url });
  } catch (error) {
    console.error('Stripe checkout error:', error);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Stripe webhook handler
app.post('/api/stripe-webhook', async (req, res) => {
  console.log(`🎣 Stripe webhook received - Event type: ${req.body ? 'BODY_EXISTS' : 'NO_BODY'}`);
  
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
  
  if (!endpointSecret) {
    console.error('❌ STRIPE_WEBHOOK_SECRET not configured');
    return res.status(500).send('Webhook secret not configured');
  }
  
  let event;
  
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    console.log(`✅ Webhook verified successfully - Event type: ${event.type}`);
  } catch (err) {
    console.error('❌ Webhook signature verification failed:', err.message);
    return res.status(400).send('Webhook signature verification failed');
  }
  
  try {
    switch (event.type) {
      case 'checkout.session.completed':
        const session = event.data.object;

        // Check if this is a citation building order
        if (session.metadata.service_type === 'citation_building') {
          console.log('📋 Citation building order detected');

          // Parse priority citations from metadata
          let priorityCitations = [];
          let existingCitations = [];

          try {
            if (session.metadata.priority_citations) {
              priorityCitations = JSON.parse(session.metadata.priority_citations);
            }
            if (session.metadata.existing_citations) {
              existingCitations = JSON.parse(session.metadata.existing_citations);
            }
          } catch (parseError) {
            console.error('Error parsing citation data:', parseError);
          }

          // Get user info for email
          const userId = parseInt(session.metadata.user_id);
          const user = await db.get('SELECT first_name, last_name, email FROM users WHERE id = $1', [userId]);

          const customerName = user ? `${user.first_name} ${user.last_name}` : 'Unknown';
          const customerEmail = user ? user.email : session.customer_email || 'Unknown';

          // Send citation order notification email
          await sendCitationOrderEmail({
            packageSize: parseInt(session.metadata.package_size),
            businessName: session.metadata.business_name,
            businessAddress: session.metadata.business_address,
            businessPhone: session.metadata.business_phone,
            customerName: customerName,
            customerEmail: customerEmail,
            amountPaid: session.amount_total,
            priorityCitations: priorityCitations,
            existingCitations: existingCitations,
            missingCount: parseInt(session.metadata.missing_count || 0),
            foundCount: parseInt(session.metadata.found_count || 0),
            totalAnalyzed: parseInt(session.metadata.total_analyzed || 0)
          });

          console.log(`✅ Citation order processed and notification sent`);
          break;
        }

        // Handle successful payment (credit purchases)
        const userId = parseInt(session.metadata.userId);
        const credits = parseInt(session.metadata.credits);
        let priceType = session.metadata.priceType;

        // Handle backward compatibility for old plan names
        if (priceType === 'starter') {
          priceType = 'pro'; // Map old 'starter' to new 'pro'
          console.log('🔄 Mapped legacy "starter" plan to "pro"');
        } else if (priceType === 'pro') {
          priceType = 'premium'; // Map old 'pro' to new 'premium'
          console.log('🔄 Mapped legacy "pro" plan to "premium"');
        }

        // Check for duplicate payment processing
        const existingPayment = await db.query(
          'SELECT id FROM payments WHERE stripe_session_id = $1',
          [session.id]
        );

        if (existingPayment.rows && existingPayment.rows.length > 0) {
          console.log(`⚠️ Payment already processed for session ${session.id}`);
          break;
        }

        // Update user credits
        await db.query(
          'UPDATE users SET credits_remaining = credits_remaining + $1 WHERE id = $2',
          [credits, userId]
        );

        // Record payment
        await db.query(`
          INSERT INTO payments (
            user_id, stripe_session_id, stripe_payment_intent_id,
            amount, status, product_type, credits_purchased
          ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [
          userId,
          session.id,
          session.payment_intent || session.subscription,
          session.amount_total,
          'completed',
          priceType,
          credits
        ]);

        // Update subscription tier if applicable
        if (priceType === 'pro' || priceType === 'premium') {
          await db.query(
            'UPDATE users SET subscription_tier = $1 WHERE id = $2',
            [priceType, userId]
          );
        }

        console.log(`✅ Payment successful for user ${userId}: ${credits} credits added`);
        console.log(`🔍 DEBUG - Session data:`, {
          sessionId: session.id,
          userId: userId,
          credits: credits,
          priceType: priceType,
          metadata: session.metadata,
          paymentIntent: session.payment_intent,
          amountTotal: session.amount_total
        });
        break;
        
      case 'customer.subscription.deleted':
        // Handle subscription cancellation
        const subscription = event.data.object;
        const customer = await stripe.customers.retrieve(subscription.customer);
        
        if (customer.email) {
          await db.query(
            'UPDATE users SET subscription_tier = $1 WHERE email = $2',
            ['free', customer.email]
          );
          console.log(`❌ Subscription cancelled for ${customer.email}`);
        }
        break;
    }
    
    res.json({ received: true });
  } catch (error) {
    console.error('Webhook processing error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Billing History endpoint
app.get('/api/billing-history', authenticateToken, async (req, res) => {
  try {
    console.log(`📋 Fetching billing history for user ${req.user.id}`);
    
    // Get all payments for this user
    const payments = await db.query(`
      SELECT 
        stripe_session_id,
        stripe_payment_intent_id,
        amount,
        status,
        product_type,
        credits_purchased,
        created_at
      FROM payments 
      WHERE user_id = $1 
      ORDER BY created_at DESC
    `, [req.user.id]);
    
    // Format the payment data for display
    const formattedPayments = payments.rows.map(payment => ({
      id: payment.stripe_session_id,
      date: new Date(payment.created_at).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      }),
      amount: (payment.amount / 100).toFixed(2), // Convert cents to dollars
      credits: payment.credits_purchased,
      planType: formatPlanName(payment.product_type),
      status: payment.status.charAt(0).toUpperCase() + payment.status.slice(1),
      stripeSessionId: payment.stripe_session_id
    }));
    
    console.log(`✅ Found ${formattedPayments.length} payments for user`);
    
    res.json({
      success: true,
      payments: formattedPayments,
      totalPayments: formattedPayments.length
    });
    
  } catch (error) {
    console.error('❌ Billing history error:', error);
    res.status(500).json({ error: 'Failed to fetch billing history' });
  }
});

// Cancel Subscription endpoint
app.post('/api/cancel-subscription', authenticateToken, async (req, res) => {
  try {
    console.log(`🚫 Cancellation request from user ${req.user.id} (${req.user.email})`);
    
    const { reason, feedback, timestamp } = req.body;
    
    // Log cancellation to console for immediate visibility
    console.log('════════════════════════════════════════════════════════════════');
    console.log('🚫 SUBSCRIPTION CANCELLATION REQUEST');
    console.log('════════════════════════════════════════════════════════════════');
    console.log(`User ID: ${req.user.id}`);
    console.log(`Email: ${req.user.email}`);
    console.log(`Name: ${req.user.firstName} ${req.user.lastName}`);
    console.log(`Current Plan: ${req.user.subscriptionTier}`);
    console.log(`Credits Remaining: ${req.user.creditsRemaining}`);
    console.log(`Reason: ${reason}`);
    console.log(`Feedback: ${feedback || 'No additional feedback'}`);
    console.log(`Timestamp: ${timestamp}`);
    console.log('════════════════════════════════════════════════════════════════');
    
    // Update user subscription status
    await db.query(
      'UPDATE users SET subscription_tier = $1, credits_remaining = $2 WHERE id = $3',
      ['free', 0, req.user.id]
    );
    
    // Store cancellation record (optional - you could create a cancellations table)
    console.log('📝 Storing cancellation details for records...');
    
    // Send webhook notification if configured
    const CANCELLATION_WEBHOOK_URL = process.env.CANCELLATION_WEBHOOK_URL;
    if (CANCELLATION_WEBHOOK_URL) {
      try {
        console.log('📤 Sending cancellation webhook...');
        await axios.post(CANCELLATION_WEBHOOK_URL, {
          event: 'subscription_cancelled',
          user: {
            id: req.user.id,
            email: req.user.email,
            name: `${req.user.firstName} ${req.user.lastName}`,
            previousPlan: req.user.subscriptionTier,
            creditsLost: req.user.creditsRemaining
          },
          cancellation: {
            reason: reason,
            feedback: feedback,
            timestamp: timestamp
          }
        }, {
          timeout: 5000
        });
        console.log('✅ Cancellation webhook sent successfully');
      } catch (webhookError) {
        console.error('⚠️ Cancellation webhook failed:', webhookError.message);
        // Continue even if webhook fails
      }
    }
    
    console.log(`✅ Subscription cancelled successfully for user ${req.user.id}`);
    
    res.json({
      success: true,
      message: 'Subscription cancelled successfully'
    });
    
  } catch (error) {
    console.error('❌ Cancellation error:', error);
    res.status(500).json({ error: 'Failed to cancel subscription' });
  }
});

// Helper function to format plan names for display
function formatPlanName(productType) {
  const planNames = {
    'oneTime': 'Single Report',
    'pro': 'Pro Plan (50 Credits)',
    'premium': 'Premium Plan (100 Credits)',
    'starter': 'Pro Plan (50 Credits)', // Legacy compatibility
    'professional': 'Premium Plan (100 Credits)'
  };
  return planNames[productType] || productType;
}

// DEBUG: Check recent payments and webhook activity
app.get('/api/debug/payments', authenticateToken, async (req, res) => {
  try {
    // Get recent payments for this user
    const payments = await db.query(
      'SELECT * FROM payments WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10',
      [req.user.id]
    );
    
    // Get user's current credits
    const user = await db.query(
      'SELECT credits_remaining, subscription_tier FROM users WHERE id = $1',
      [req.user.id]
    );
    
    res.json({
      success: true,
      userCredits: user.rows[0]?.credits_remaining || 0,
      subscriptionTier: user.rows[0]?.subscription_tier || 'free',
      recentPayments: payments.rows || []
    });
  } catch (error) {
    console.error('Debug payments error:', error);
    res.status(500).json({ error: 'Failed to fetch payment debug info' });
  }
});

// ==========================================
// WHITE LABEL API ENDPOINTS
// ==========================================

// Get white label settings for a user
app.get('/api/white-label', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT custom_brand_name, custom_brand_logo, custom_prepared_by, custom_primary_color, custom_contact_name, custom_contact_email, custom_contact_phone, white_label_enabled FROM users WHERE id = $1',
      [req.user.id]
    );
    
    if (result.rows && result.rows.length > 0) {
      res.json(result.rows[0]);
    } else {
      res.json({
        custom_brand_name: null,
        custom_brand_logo: null,
        custom_prepared_by: null,
        custom_primary_color: null,
        custom_contact_name: null,
        custom_contact_email: null,
        custom_contact_phone: null,
        white_label_enabled: false
      });
    }
  } catch (error) {
    console.error('Error fetching white label settings:', error);
    res.status(500).json({ error: 'Failed to fetch white label settings' });
  }
});

// Update white label settings (only for subscription users)
app.post('/api/white-label', authenticateToken, async (req, res) => {
  try {
    // Check if user has subscription
    const userResult = await db.query('SELECT subscription_tier FROM users WHERE id = $1', [req.user.id]);
    
    if (!userResult.rows || userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = userResult.rows[0];
    if (user.subscription_tier === 'free') {
      return res.status(403).json({ error: 'White label customization is only available for subscription users' });
    }
    
    const {
      custom_brand_name,
      custom_brand_logo,
      custom_prepared_by,
      custom_primary_color,
      custom_contact_name,
      custom_contact_email,
      custom_contact_phone,
      white_label_enabled,
      remove_logo_completely
    } = req.body;
    
    // Handle remove logo completely option
    const finalLogo = remove_logo_completely ? null : custom_brand_logo;
    
    await db.query(
      `UPDATE users SET 
        custom_brand_name = $1,
        custom_brand_logo = $2,
        custom_prepared_by = $3,
        custom_primary_color = $4,
        custom_contact_name = $5,
        custom_contact_email = $6,
        custom_contact_phone = $7,
        white_label_enabled = $8,
        updated_at = CURRENT_TIMESTAMP
       WHERE id = $9`,
      [
        custom_brand_name,
        finalLogo,
        custom_prepared_by,
        custom_primary_color,
        custom_contact_name,
        custom_contact_email,
        custom_contact_phone,
        white_label_enabled,
        req.user.id
      ]
    );
    
    res.json({ success: true, message: 'White label settings updated successfully' });
    
    console.log(`🎨 User ${req.user.id} updated white label settings:`, {
      brand_name: custom_brand_name,
      enabled: white_label_enabled
    });
    
  } catch (error) {
    console.error('Error updating white label settings:', error);
    res.status(500).json({ error: 'Failed to update white label settings' });
  }
});

// Update user account settings
app.put('/api/user/update', authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, currentPassword, newPassword } = req.body;
    const updates = [];
    const values = [];
    let valueIndex = 1;
    
    // Handle name updates
    if (firstName !== undefined) {
      updates.push(`first_name = $${valueIndex++}`);
      values.push(firstName);
    }
    
    if (lastName !== undefined) {
      updates.push(`last_name = $${valueIndex++}`);
      values.push(lastName);
    }
    
    // Handle password update
    if (newPassword && currentPassword) {
      // Verify current password
      const user = await db.get('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      const passwordMatch = await bcrypt.compare(currentPassword, user.password_hash);
      
      if (!passwordMatch) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }
      
      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      updates.push(`password_hash = $${valueIndex++}`);
      values.push(hashedPassword);
    }
    
    // Only update if there are changes
    if (updates.length === 0) {
      return res.json({ success: true, message: 'No changes to update' });
    }
    
    // Add updated_at for PostgreSQL, skip for SQLite
    if (db.dbType === 'postgresql') {
      updates.push(`updated_at = CURRENT_TIMESTAMP`);
    }
    
    // Add user ID for WHERE clause
    values.push(req.user.id);
    
    // Execute update
    const updateQuery = `UPDATE users SET ${updates.join(', ')} WHERE id = $${valueIndex}`;
    await db.run(updateQuery, values);
    
    // Get updated user data
    const updatedUser = await db.get('SELECT first_name, last_name FROM users WHERE id = $1', [req.user.id]);
    
    if (updatedUser) {
      res.json({
        success: true,
        message: 'Account settings updated successfully',
        user: {
          firstName: updatedUser.first_name,
          lastName: updatedUser.last_name
        }
      });
    } else {
      res.status(500).json({ error: 'Failed to update account settings' });
    }
    
  } catch (error) {
    console.error('Error updating user account:', error);
    res.status(500).json({ error: 'Failed to update account settings' });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down gracefully...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    } else {
      console.log('✅ Database connection closed');
    }
    process.exit(0);
  });
});

// ==========================================
// ENHANCED CITATION ANALYSIS - TEST FUNCTIONS
// ==========================================

// Generate business name variations for more accurate citation searches
function generateBusinessNameVariations(businessName) {
  const variations = [businessName]; // Start with original name
  
  // Common business suffixes to try adding/removing
  const suffixes = ['LLC', 'Inc', 'Corp', 'Company', 'Co', 'Ltd', 'LTD', 'INC'];
  const serviceWords = ['Services', 'Service', 'Group', 'Solutions', 'Enterprises'];
  
  // Remove suffixes if present
  let baseName = businessName;
  suffixes.forEach(suffix => {
    const regex = new RegExp(`\\s+(${suffix})\\.?$`, 'i');
    if (regex.test(baseName)) {
      baseName = baseName.replace(regex, '').trim();
      if (!variations.includes(baseName)) {
        variations.push(baseName);
      }
    }
  });
  
  // Add suffixes if not present
  suffixes.forEach(suffix => {
    const withSuffix = `${baseName} ${suffix}`;
    if (!variations.includes(withSuffix)) {
      variations.push(withSuffix);
    }
  });
  
  // Try with/without service words
  serviceWords.forEach(word => {
    const withWord = `${baseName} ${word}`;
    const withoutWord = baseName.replace(new RegExp(`\\s+${word}$`, 'i'), '').trim();
    
    if (!variations.includes(withWord)) {
      variations.push(withWord);
    }
    if (withoutWord !== baseName && !variations.includes(withoutWord)) {
      variations.push(withoutWord);
    }
  });
  
  console.log(`🔍 Generated ${variations.length} name variations:`, variations);
  return variations;
}

// Enhanced citation checker with name variations and NAP detection
async function checkCitationsEnhanced(businessName, phoneNumber, address = '') {
  try {
    console.log(`🔍 ENHANCED CITATION CHECK: ${businessName}`);
    
    if (!SERPAPI_KEY) {
      throw new Error('SerpAPI key not configured');
    }
    
    const nameVariations = generateBusinessNameVariations(businessName);
    const phonePatterns = generatePhoneSearchPatterns(phoneNumber);
    
    const directories = [
      { name: 'Angi', domain: 'angi.com' },
      { name: 'Apple Maps Business Connect', domain: 'mapsconnect.apple.com' },
      { name: 'Better Business Bureau', domain: 'bbb.org' },
      { name: 'Bing Places', domain: 'bing.com/maps' },
      { name: 'Chamber of Commerce', domain: 'chamberofcommerce.com' },
      { name: 'DNB (Dun & Bradstreet)', domain: 'dnb.com' },
      { name: 'Facebook', domain: 'facebook.com' },
      { name: 'Foursquare', domain: 'foursquare.com' },
      { name: 'Nextdoor', domain: 'nextdoor.com' },
      { name: 'Yelp', domain: 'yelp.com' }
    ];
    
    const results = [];
    
    for (const directory of directories) {
      console.log(`🔍 Searching ${directory.name}...`);
      
      let bestMatch = null;
      let napStatus = 'not_found';
      let warnings = [];
      
      // Try each name variation
      for (const nameVariation of nameVariations) {
        try {
          // Try with phone first, then without
          const searchQueries = [];
          
          if (phonePatterns.length > 0) {
            searchQueries.push(`site:${directory.domain} "${nameVariation}" "${phonePatterns[0]}"`);
          }
          searchQueries.push(`site:${directory.domain} "${nameVariation}"`);
          
          for (const searchQuery of searchQueries) {
            const response = await axios.get('https://serpapi.com/search.json', {
              params: {
                engine: 'google',
                q: searchQuery,
                api_key: SERPAPI_KEY,
                num: 3,
                google_domain: 'google.com',
                gl: 'us',
                hl: 'en'
              },
              timeout: 10000
            });
            
            if (response.data.organic_results && response.data.organic_results.length > 0) {
              for (const result of response.data.organic_results) {
                const resultText = `${result.title || ''} ${result.snippet || ''}`.toLowerCase();
                const nameFound = resultText.includes(nameVariation.toLowerCase());
                
                if (nameFound) {
                  // Check NAP consistency
                  const napAnalysis = analyzeNAPConsistency(result, businessName, phoneNumber, address);
                  
                  if (!bestMatch || napAnalysis.score > bestMatch.napAnalysis.score) {
                    bestMatch = {
                      directory: directory.name,
                      domain: directory.domain,
                      url: result.link,
                      title: result.title,
                      snippet: result.snippet,
                      nameVariation: nameVariation,
                      searchQuery: searchQuery,
                      napAnalysis: napAnalysis
                    };
                    napStatus = napAnalysis.status;
                    warnings = napAnalysis.warnings;
                  }
                  break; // Found a match for this name variation
                }
              }
              
              if (bestMatch) break; // Found a good match, no need to try more queries
            }
            
            // Small delay between searches
            await new Promise(resolve => setTimeout(resolve, 300));
          }
          
          if (bestMatch) break; // Found a match, no need to try more name variations
          
        } catch (searchError) {
          console.error(`❌ Search error for ${nameVariation} on ${directory.name}:`, searchError.message);
        }
      }
      
      results.push({
        directory: directory.name,
        domain: directory.domain,
        found: !!bestMatch,
        napStatus: napStatus,
        warnings: warnings,
        result: bestMatch,
        searchAttempts: nameVariations.length
      });
      
      // Longer delay between directories to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    const foundCount = results.filter(r => r.found).length;
    const napIssues = results.filter(r => r.warnings.length > 0).length;
    
    console.log(`📊 ENHANCED RESULTS: ${foundCount}/${directories.length} found, ${napIssues} with NAP issues`);
    
    return {
      found: results.filter(r => r.found),
      results: results,
      total: directories.length,
      stats: {
        found: foundCount,
        missing: directories.length - foundCount,
        napIssues: napIssues,
        percentage: Math.round((foundCount / directories.length) * 100),
        score: foundCount // 1 point per citation found
      }
    };
    
  } catch (error) {
    console.error('❌ Enhanced citation check error:', error.message);
    throw new Error(`Enhanced citation check failed: ${error.message}`);
  }
}

// Analyze NAP (Name, Address, Phone) consistency
function analyzeNAPConsistency(result, expectedName, expectedPhone, expectedAddress) {
  const resultText = `${result.title || ''} ${result.snippet || ''}`;
  const warnings = [];
  let score = 0;
  
  // Check name consistency (basic)
  const nameMatch = resultText.toLowerCase().includes(expectedName.toLowerCase());
  if (nameMatch) score += 3;
  
  // Check phone consistency
  if (expectedPhone) {
    const phonePatterns = generatePhoneSearchPatterns(expectedPhone);
    const phoneFound = phonePatterns.some(pattern => 
      resultText.toLowerCase().includes(pattern.toLowerCase()) ||
      resultText.includes(normalizePhoneNumber(pattern))
    );
    
    if (phoneFound) {
      score += 3;
    } else {
      warnings.push({
        type: 'phone_mismatch',
        message: 'Phone number not found or doesn\'t match',
        severity: 'warning'
      });
    }
  }
  
  // Check for common NAP issues
  if (resultText.includes('permanently closed') || resultText.includes('out of business')) {
    warnings.push({
      type: 'business_closed',
      message: 'Directory shows business as closed',
      severity: 'error'
    });
  }
  
  // Check for address inconsistencies (basic)
  if (expectedAddress && expectedAddress.length > 10) {
    const addressParts = expectedAddress.split(',').map(part => part.trim().toLowerCase());
    const addressFound = addressParts.some(part => 
      part.length > 3 && resultText.toLowerCase().includes(part)
    );
    
    if (addressFound) {
      score += 2;
    } else {
      warnings.push({
        type: 'address_mismatch',
        message: 'Address may not match expected location',
        severity: 'warning'
      });
    }
  }
  
  // Determine overall status
  let status = 'not_found';
  if (score >= 6) status = 'good';
  else if (score >= 3) status = 'partial';
  else if (warnings.length > 0) status = 'issues';
  
  return {
    score: score,
    status: status,
    warnings: warnings,
    matchedElements: {
      name: nameMatch,
      phone: expectedPhone ? score >= 3 : null,
      address: expectedAddress ? score >= 2 : null
    }
  };
}

// Test endpoint for enhanced citation analysis
app.post('/api/test/enhanced-citations', async (req, res) => {
  try {
    const { businessName, phoneNumber, address } = req.body;
    
    console.log(`🧪 TESTING Enhanced Citation Analysis`);
    console.log(`Business: ${businessName}`);
    console.log(`Phone: ${phoneNumber}`);
    console.log(`Address: ${address}`);
    
    if (!businessName) {
      return res.status(400).json({ error: 'Business name is required' });
    }
    
    if (!SERPAPI_KEY) {
      return res.status(500).json({ error: 'SerpAPI key not configured' });
    }
    
    const startTime = Date.now();
    
    // Run both old and new analysis for comparison
    console.log('🔄 Running original citation analysis...');
    const originalResults = await checkCitations(businessName, phoneNumber);
    
    console.log('🚀 Running enhanced citation analysis...');
    const enhancedResults = await checkCitationsEnhanced(businessName, phoneNumber, address);
    
    const duration = Date.now() - startTime;
    
    res.json({
      success: true,
      testResults: {
        original: {
          found: originalResults.found.length,
          score: originalResults.stats.score,
          results: originalResults.found.map(f => ({ directory: f.directory, url: f.url }))
        },
        enhanced: {
          found: enhancedResults.stats.found,
          score: enhancedResults.stats.score,
          napIssues: enhancedResults.stats.napIssues,
          results: enhancedResults.results.map(r => ({
            directory: r.directory,
            found: r.found,
            napStatus: r.napStatus,
            warnings: r.warnings,
            url: r.result?.url,
            nameVariation: r.result?.nameVariation,
            searchAttempts: r.searchAttempts
          }))
        },
        comparison: {
          improvementFound: enhancedResults.stats.found - originalResults.found.length,
          newIssuesDetected: enhancedResults.stats.napIssues,
          duration: `${duration}ms`
        }
      }
    });
    
  } catch (error) {
    console.error('❌ Enhanced citation test error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==========================================
// APPSUMO LIFETIME CREDIT RENEWAL CRON
// ==========================================

// Renew credits for lifetime AppSumo users monthly
async function renewLifetimeCredits() {
  try {
    console.log('🔄 Running lifetime credit renewal...');

    // Get all lifetime users who need renewal (last renewal > 30 days ago or null)
    const lifetimeUsers = await db.all(`
      SELECT id, email, lifetime_monthly_credits, last_credit_renewal, appsumo_plan_id
      FROM users
      WHERE is_lifetime = $1
      AND (
        last_credit_renewal IS NULL
        OR last_credit_renewal < NOW() - INTERVAL '30 days'
      )
    `, [true]);

    if (lifetimeUsers.length === 0) {
      console.log('✅ No lifetime users need credit renewal');
      return;
    }

    console.log(`🔄 Renewing credits for ${lifetimeUsers.length} lifetime users...`);

    for (const user of lifetimeUsers) {
      try {
        await db.query(`
          UPDATE users
          SET credits_remaining = $1,
              last_credit_renewal = NOW()
          WHERE id = $2
        `, [user.lifetime_monthly_credits, user.id]);

        console.log(`✅ Renewed ${user.lifetime_monthly_credits} credits for ${user.email} (AppSumo ${user.appsumo_plan_id})`);
      } catch (userError) {
        console.error(`❌ Failed to renew credits for user ${user.email}:`, userError.message);
      }
    }

    console.log(`✅ Lifetime credit renewal complete: ${lifetimeUsers.length} users renewed`);

  } catch (error) {
    console.error('❌ Lifetime credit renewal error:', error);
  }
}

// Run credit renewal daily at 2 AM
setInterval(renewLifetimeCredits, 24 * 60 * 60 * 1000); // Every 24 hours

// Also run on server start (for any missed renewals)
setTimeout(renewLifetimeCredits, 5000); // Run 5 seconds after server starts

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Local SEO Audit v3 (COMPLETE) running on http://localhost:${PORT}`);
  console.log('');
  console.log('🎯 COMPLETE VERSION - ALL FEATURES:');
  console.log('✅ Complete 12-factor scoring system (100 points)');
  console.log('✅ Outscraper integration with async polling');
  console.log('✅ ScrapingBee screenshot capture');
  console.log('✅ OpenAI screenshot analysis (posts, tiles, Q&A, social)');
  console.log('✅ Citation checking across 7 directories');
  console.log('✅ Website analysis (GBP embed + service extraction)');
  console.log('✅ SerpAPI reviews analysis');
  console.log('✅ AI-powered smart suggestions');
  console.log('✅ Complete action plan generation');
  console.log('✅ Production-ready error handling');
  console.log('');
  console.log('🔧 API STATUS:');
  console.log(`📍 Outscraper: ${OUTSCRAPER_API_KEY ? '✅ Ready' : '❌ Missing'}`);
  console.log(`📸 ScrapingBee: ${SCRAPINGBEE_API_KEY ? '✅ Ready' : '❌ Missing'}`);
  console.log(`🤖 OpenAI: ${OPENAI_API_KEY ? '✅ Ready' : '❌ Missing'}`);
  console.log(`🔍 SerpAPI: ${SERPAPI_KEY ? '✅ Ready' : '❌ Missing'}`);
  console.log('');
  console.log(`🏷️ Brand: ${BRAND_CONFIG.name}`);
  console.log(`💰 Estimated cost per report: ~$0.085`);
  console.log(`📈 Profit margin: 99.83% at $49/report`);
  console.log('');
  console.log('🚀 Ready for production deployment!');
});

// Webhook configuration debug endpoint
app.get('/api/webhook-config', (req, res) => {
  const config = {
    stripe: {
      webhookSecret: process.env.STRIPE_WEBHOOK_SECRET ? 
        (process.env.STRIPE_WEBHOOK_SECRET.startsWith('whsec_') ? 'CONFIGURED' : 'PLACEHOLDER') : 'NOT_SET',
      secretKey: process.env.STRIPE_SECRET_KEY ? 'CONFIGURED' : 'NOT_SET'
    },
    email: {
      feedbackWebhook: process.env.FEEDBACK_WEBHOOK_URL ? 'CONFIGURED' : 'NOT_SET',
      emailWebhook: process.env.EMAIL_WEBHOOK_URL ? 'CONFIGURED' : 'NOT_SET',
      emailVerificationWebhook: process.env.EMAIL_VERIFICATION_WEBHOOK_URL ? 'CONFIGURED' : 'NOT_SET',
      passwordResetWebhook: process.env.PASSWORD_RESET_WEBHOOK_URL ? 'CONFIGURED' : 'NOT_SET',
      newUserWebhook: process.env.NEW_USER_WEBHOOK_URL ? 'CONFIGURED' : 'NOT_SET'
    },
    app: {
      appUrl: process.env.APP_URL || 'NOT_SET',
      environment: process.env.NODE_ENV || 'development'
    },
    webhookUrls: {
      feedback: process.env.FEEDBACK_WEBHOOK_URL,
      email: process.env.EMAIL_WEBHOOK_URL,
      emailVerification: process.env.EMAIL_VERIFICATION_WEBHOOK_URL,
      passwordReset: process.env.PASSWORD_RESET_WEBHOOK_URL,
      newUser: process.env.NEW_USER_WEBHOOK_URL
    }
  };
  
  console.log('🔧 Webhook configuration requested');
  res.json(config);
});

// Emergency fix for subscription issue
app.post('/api/emergency-fix-subscription', async (req, res) => {
  try {
    const { email, subscriptionTier, credits } = req.body;
    
    // Security check - only allow fixing me@me.com
    if (email !== 'me@me.com') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    console.log(`🚑 Emergency subscription fix for: ${email}`);
    
    // Update user subscription and credits
    await db.query(
      'UPDATE users SET subscription_tier = $1, credits_remaining = credits_remaining + $2 WHERE email = $3',
      [subscriptionTier || 'starter', credits || 50, email]
    );
    
    // Check if update was successful
    const user = await db.get('SELECT * FROM users WHERE email = $1', [email]);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    console.log(`✅ Emergency fix applied: ${user.email} now has ${user.credits_remaining} credits and ${user.subscription_tier} subscription`);
    
    res.json({
      success: true,
      message: `Subscription fixed for ${email}`,
      user: {
        email: user.email,
        creditsRemaining: user.credits_remaining,
        subscriptionTier: user.subscription_tier
      }
    });
    
  } catch (error) {
    console.error('❌ Emergency fix error:', error);
    res.status(500).json({ error: 'Fix failed', details: error.message });
  }
});
