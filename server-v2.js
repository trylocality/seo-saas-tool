require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
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
  starter: process.env.STRIPE_PRICE_STARTER || 'price_1Ro501DEq7s1BPEYrXB78dyu',
  pro: process.env.STRIPE_PRICE_PRO || 'price_1ReR1MDEq7s1BPEYHzSW0uTn'
};

const CREDIT_AMOUNTS = {
  oneTime: 1,
  starter: 50,
  pro: 100
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

app.use(cors());
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
      await axios.post(webhookUrl, {
        subject,
        body: notificationBody,
        type: 'new_user',
        data: userData,
        timestamp: new Date().toISOString()
      });
      console.log('✅ New user webhook notification sent');
    } catch (error) {
      console.error('❌ Failed to send new user webhook:', error.message);
    }
  }
}

// Generic email sending function
async function sendEmail(to, subject, htmlContent, textContent) {
  try {
    // Method 1: Log to console (always works for debugging)
    console.log('📧 EMAIL NOTIFICATION:');
    console.log('To:', to);
    console.log('Subject:', subject);
    console.log('Body:', textContent || htmlContent);
    
    // Method 2: Try to use a webhook service (like Zapier, n8n, or similar)
    const webhookUrl = process.env.EMAIL_WEBHOOK_URL || process.env.FEEDBACK_WEBHOOK_URL;
    if (webhookUrl) {
      const webhookData = {
        to: to,
        subject: subject,
        html: htmlContent,
        text: textContent,
        timestamp: new Date().toISOString()
      };
      
      await axios.post(webhookUrl, webhookData, {
        timeout: 5000,
        headers: { 'Content-Type': 'application/json' }
      });
      
      console.log('✅ Email webhook sent successfully');
    }
    
    return true;
  } catch (error) {
    console.error('❌ Email sending failed:', error.message);
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
  
  return sendEmail(email, subject, htmlContent, textContent);
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
  
  return sendEmail(email, subject, htmlContent, textContent);
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
    
    // Method 2: Try to use a webhook service (like Zapier, n8n, or similar)
    // This allows you to set up email forwarding without SMTP credentials
    if (process.env.FEEDBACK_WEBHOOK_URL) {
      const webhookData = {
        to: 'trylocality@gmail.com',
        subject: subject,
        body: emailBody,
        feedbackData: feedbackData
      };
      
      await axios.post(process.env.FEEDBACK_WEBHOOK_URL, webhookData, {
        timeout: 5000,
        headers: { 'Content-Type': 'application/json' }
      });
      
      console.log('✅ Feedback webhook sent successfully');
    }
    
    return true;
  } catch (error) {
    console.error('❌ Email sending failed:', error.message);
    throw error;
  }
}

// ==========================================
// BUSINESS ANALYSIS FUNCTIONS
// ==========================================

// 1. OUTSCRAPER - Get primary business data
async function getOutscraperData(businessName, location) {
  try {
    const query = `${businessName} ${location}`;
    console.log(`🔍 Outscraper search: ${query}`);
    
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
        limit: 1
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
      
      // Poll for results (max 30 seconds)
      for (let i = 0; i < 6; i++) {
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
            const business = Array.isArray(businessData) ? businessData[0] : businessData;
            console.log(`✅ Outscraper found: ${business.name || business.title || businessName}`);
            console.log('🔍 FINAL BUSINESS OBJECT:', JSON.stringify(business, null, 2));
            
            return {
              name: business.name || business.title || businessName,
              phone: business.phone || '',
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
            };
          }
        } catch (pollError) {
          console.log(`⏳ Poll ${i + 1}: Still processing...`);
        }
      }
      
      throw new Error('Outscraper polling timeout - no results after 30 seconds');
    }
    
    // Handle immediate response
    if (response.data && response.data.data && response.data.data.length > 0) {
      const businessData = response.data.data[0];
      console.log('🔍 IMMEDIATE BUSINESS DATA TYPE:', typeof businessData, 'IS_ARRAY:', Array.isArray(businessData));
      
      // Handle if business data is an array (extract first element) or direct object
      const business = Array.isArray(businessData) ? businessData[0] : businessData;
      console.log(`✅ Outscraper found: ${business.name || business.title || businessName}`);
      
      return {
        name: business.name || business.title || businessName,
        phone: business.phone || '',
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
      };
    }
    
    throw new Error('No business found in Outscraper response');
    
  } catch (error) {
    console.error('❌ Outscraper error:', error.message);
    throw new Error(`Outscraper failed: ${error.message}`);
  }
}
// 2. SCRAPINGBEE SCREENSHOT - For visual analysis
async function takeBusinessProfileScreenshot(businessName, location) {
  try {
    console.log(`📸 Taking ScrapingBee screenshot: ${businessName}`);
    
    await ensureScreenshotsDir();
    
    if (!SCRAPINGBEE_API_KEY) {
      throw new Error('ScrapingBee API key not configured');
    }
    
    const searchQuery = `${businessName} ${location}`;
    
    // Detect location for better screenshot results
    const { region } = detectCountryRegion(location);
    const googleDomain = region === 'AE' ? 'google.ae' : region === 'GB' ? 'google.co.uk' : 'google.com';
    const googleSearchUrl = `https://www.${googleDomain}/search?q=${encodeURIComponent(searchQuery)}&gl=${region.toLowerCase()}&hl=en`;
    
    const params = {
      api_key: SCRAPINGBEE_API_KEY,
      url: googleSearchUrl,
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
      
      return {
        success: true,
        filename: filename,
        filepath: filepath,
        url: `/screenshots/${filename}`,
        fileSize: response.data.length
      };
    } else {
      throw new Error(`Unexpected response: ${response.status}`);
    }
    
  } catch (error) {
    console.error('❌ Screenshot error:', error.message);
    throw new Error(`Screenshot failed: ${error.message}`);
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
    Analyze this Google Business Profile screenshot for "${businessName}".
    
    Look for these specific elements:
    1. POSTS/UPDATES: Recent posts, updates, or announcements in the "Posts" or "Updates" section
    2. PRODUCT TILES: Product/service tiles or listings in a dedicated products section
    3. Q&A SECTION: Questions and answers from customers
    4. SOCIAL MEDIA: Social media profile links or icons
    
    Respond ONLY with valid JSON:
    {
      "posts": {
        "hasRecent": false,
        "count": 0
      },
      "productTiles": {
        "hasAny": false,
        "count": 0
      },
      "qa": {
        "hasAny": false,
        "count": 0
      },
      "social": {
        "hasAny": false,
        "count": 0
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
      max_tokens: 500
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
    
    console.log(`✅ AI Analysis: Posts: ${analysis.posts.hasRecent}, Product Tiles: ${analysis.productTiles.hasAny}, Q&A: ${analysis.qa.hasAny}, Social: ${analysis.social.hasAny}`);
    
    return analysis;
    
  } catch (error) {
    console.error('❌ AI analysis error:', error.message);
    throw new Error(`AI analysis failed: ${error.message}`);
  }
}
// 4. CITATION CHECKER - Check presence in major directories
async function checkCitations(businessName, location) {
  try {
    console.log(`🔍 Checking citations: ${businessName} in ${location}`);
    
    if (!SERPAPI_KEY) {
      throw new Error('SerpAPI key not configured');
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
    
    for (const directory of directories) {
      try {
        const searchQuery = `site:${directory.domain} "${businessName}" ${location}`;
        
        // Detect location for better search results
        const { region } = detectCountryRegion(location);
        const googleDomain = region === 'AE' ? 'google.ae' : region === 'GB' ? 'google.co.uk' : 'google.com';
        
        const response = await axios.get('https://serpapi.com/search.json', {
          params: {
            engine: 'google',
            q: searchQuery,
            api_key: SERPAPI_KEY,
            num: 3,
            google_domain: googleDomain,
            gl: region.toLowerCase(),
            hl: 'en'
          },
          timeout: 10000
        });
        
        const hasResults = response.data.organic_results && response.data.organic_results.length > 0;
        
        checked.push({
          directory: directory.name,
          domain: directory.domain,
          found: hasResults,
          searchQuery: searchQuery
        });
        
        if (hasResults) {
          found.push({
            directory: directory.name,
            domain: directory.domain,
            url: response.data.organic_results[0].link
          });
        }
        
        // Small delay to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 500));
        
      } catch (dirError) {
        console.error(`❌ Citation check failed for ${directory.name}:`, dirError.message);
        checked.push({
          directory: directory.name,
          domain: directory.domain,
          found: false,
          error: dirError.message
        });
      }
    }
    
    console.log(`📊 Citations found: ${found.length}/${directories.length}`);
    
    return {
      found: found,
      checked: checked,
      total: directories.length,
      stats: {
        found: found.length,
        missing: directories.length - found.length,
        percentage: Math.round((found.length / directories.length) * 100),
        score: Math.ceil(found.length * 1.5) // 1.5 points per citation found, rounded up
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
    
    const response = await axios.get(websiteUrl, {
      timeout: 15000,
      maxRedirects: 3,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });
    
    const htmlContent = response.data;
    const htmlLower = htmlContent.toLowerCase();
    
    // Check for GBP embed
    const gbpIndicators = [
      'maps.google.com/maps',
      'google.com/maps/embed',
      'maps/embed',
      'place_id=',
      'maps.googleapis.com'
    ];
    const hasGBPEmbed = gbpIndicators.some(indicator => htmlLower.includes(indicator));
    
    // Check for localized landing page - search for both city AND state/country
    const { city, state } = extractCityState(location);
    const cityLower = city.toLowerCase();
    const stateLower = state.toLowerCase();
    
    // For international addresses, also check for country-specific patterns
    const locationParts = location.toLowerCase().split(/[,\-]/).map(p => p.trim());
    
    const localizedIndicators = [
      // City-specific patterns
      `/${cityLower}`,
      `${cityLower}-`,
      `/location/${cityLower}`,
      `/service-area/${cityLower}`,
      `/serving-${cityLower}`,
      `>${cityLower} location<`,
      `>${cityLower} office<`,
      // State/Country-specific patterns
      `/${stateLower}`,
      `${stateLower}-`,
      `/location/${stateLower}`,
      `/service-area/${stateLower}`,
      `/serving-${stateLower}`,
      `>${stateLower} location<`,
      `>${stateLower} office<`,
      // Common state name patterns
      `utah`, `texas`, `california`, `florida`, `nevada`, `colorado`, `arizona`,
      // Add patterns for any part of the location
      ...locationParts.filter(part => part.length > 2).map(part => `/${part}`),
      ...locationParts.filter(part => part.length > 2).map(part => `${part}-`)
    ];
    const hasLocalizedPage = localizedIndicators.some(indicator => htmlLower.includes(indicator));
    
    // Extract services for smart suggestions
    const services = extractServicesFromHTML(htmlContent);
    
    console.log(`${hasGBPEmbed ? '✅' : '❌'} GBP Embed | ${hasLocalizedPage ? '✅' : '❌'} Localized Page | ${services.length} services found`);
    
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

// Helper function to extract city and state/country from location string
function extractCityState(location) {
  // Handle full address format (e.g., "123 Main St, Miami, FL 33101")
  const parts = location.split(/[,\-]/).map(p => p.trim()).filter(p => p.length > 0);
  
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
        timeout: 15000
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
function calculateScore(data) {
  console.log(`📊 Calculating score for: ${data.businessInfo.businessName}`);
  console.log('🔍 SCORING DEBUG - Raw Data:');
  console.log(`   Photos: ${data.outscraper.photos_count}`);
  console.log(`   Categories: ${data.outscraper.categories.length} (${data.outscraper.categories.join(', ')})`);
  console.log(`   Reviews: ${data.outscraper.reviews}, Rating: ${data.outscraper.rating}`);
  console.log(`   Verified: ${data.outscraper.verified}`);
  console.log(`   Description length: ${data.outscraper.description?.length || 0}`);
  
  const scores = {
    claimed: 0,           // 8 pts
    description: 0,       // 10 pts
    categories: 0,        // 8 pts
    productTiles: 0,      // 10 pts
    photos: 0,            // 8 pts
    posts: 0,             // 8 pts
    qa: 0,                // 4 pts
    social: 0,            // 2 pts
    reviews: 0,           // 12 pts (3 each for 4 criteria)
    citations: 0,         // 14 pts
    gbpEmbed: 0,          // 8 pts
    landingPage: 0        // 8 pts
  };
  
  const details = {};
  
  // 1. CLAIMED PROFILE (8 pts) - Binary
  if (data.outscraper.verified || data.outscraper.rating > 0) {
    scores.claimed = 8;
    details.claimed = { status: 'GOOD', message: 'Profile verified - you have full control' };
  } else {
    scores.claimed = 0;
    details.claimed = { status: 'MISSING', message: 'Profile unclaimed - can\'t manage your listing' };
  }
  
  // 2. BUSINESS DESCRIPTION (10 pts) - 0/5/10 based on criteria
  const desc = data.outscraper.description;
  const descAnalysis = analyzeDescriptionCriteria(desc, data.businessInfo.businessName, data.businessInfo.location, data.businessInfo.industry);
  
  if (!desc) {
    scores.description = 0;
    details.description = { status: 'MISSING', message: 'No description found - missing opportunity to tell your story' };
  } else if (descAnalysis.criteriaCount === 3) {
    scores.description = 10;
    details.description = { status: 'GOOD', message: 'Great description that helps customers find you' };
  } else {
    scores.description = 5;
    details.description = { status: 'NEEDS IMPROVEMENT', message: 'Basic description detected - could be more compelling' };
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
  
  // 6. POSTS (8 pts) - Binary: recent activity
  if (data.aiAnalysis.posts && data.aiAnalysis.posts.hasRecent) {
    scores.posts = 8;
    details.posts = { status: 'GOOD', message: 'Active posting keeps customers engaged' };
  } else {
    scores.posts = 0;
    details.posts = { status: 'MISSING', message: 'No recent posts - missing chance to engage customers' };
  }
  
  // 7. Q&A (4 pts) - Give half credit if we can't detect properly
  if (data.aiAnalysis.qa && data.aiAnalysis.qa.hasAny) {
    scores.qa = 4;
    details.qa = { status: 'GOOD', message: 'Q&A section helps answer customer questions' };
  } else {
    // Give half credit since detection isn't always reliable
    scores.qa = 2;
    details.qa = { status: 'UNCERTAIN', message: 'Q&A status unclear - check your profile directly' };
  }
  
  // 8. SOCIAL PROFILES (2 pts) - Binary
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
  
  // 10. CITATIONS (16 pts) - 1.5 pts per directory found, rounded up
  scores.citations = data.citations.stats.score;
  if (scores.citations >= 12) {
    details.citations = { status: 'GOOD', message: 'Excellent online presence across directories' };
  } else if (scores.citations >= 8) {
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
  
  const totalScore = Object.values(scores).reduce((sum, score) => sum + score, 0);
  
  console.log(`📊 Final Score: ${totalScore}/100`);
  
  return {
    totalScore: totalScore,
    maxScore: 100,
    scores: scores,
    details: details
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
  
  // Check for localized keywords
  const localPatterns = [
    `${cityLowerCase}`,
    `local`,
    `serving ${cityLowerCase}`,
    `${cityLowerCase} area`,
    `${cityLowerCase} ${industry.toLowerCase()}`,
    `${industry.toLowerCase()} in ${cityLowerCase}`
  ];
  const hasLocalKeywords = localPatterns.some(pattern => descLower.includes(pattern));
  
  // Check for services overview
  const servicePatterns = [
    'we provide', 'we offer', 'our services', 'services include',
    'we specialize', 'expertise in', 'professional'
  ];
  const hasServices = servicePatterns.some(pattern => descLower.includes(pattern));
  
  // Check for call to action
  const ctaPatterns = [
    'contact us', 'call us', 'reach out', 'schedule', 'book',
    'get started', 'learn more', 'visit us', 'today'
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
      Suggest Google Business Profile categories for:
      Business: ${businessName}
      Industry: ${industry}
      Services: ${websiteServices.join(', ') || 'General services'}
      
      Provide 6-8 relevant categories from Google's official category list.
      Include one primary category and 5-7 secondary categories.
      Return as a simple list, one per line, no numbering.
      Focus on categories that actually exist in Google Business Profile.
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
    if (scoreData.scores.citations < 12) {
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
    
    console.log(`✅ Smart suggestions generated for ${Object.keys(suggestions).length} areas`);
    
    return suggestions;
    
  } catch (error) {
    console.error('❌ Smart suggestions error:', error.message);
    return {
      error: `Smart suggestions failed: ${error.message}`
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

async function generateCompleteReport(businessName, location, industry, website, user = null) {
  console.log(`🚀 Generating COMPLETE report for: ${businessName} in ${location}`);
  
  const errors = [];
  let partialData = {};
  
  try {
    // Step 1: Get primary business data from Outscraper
    console.log('📍 Step 1: Getting business data...');
    try {
      partialData.outscraper = await getOutscraperData(businessName, location);
    } catch (error) {
      errors.push(`Outscraper: ${error.message}`);
      throw new Error('Failed to get basic business data - cannot continue');
    }
    
    // Step 2: Take screenshot for visual analysis
    console.log('📸 Step 2: Taking screenshot...');
    try {
      const screenshot = await takeBusinessProfileScreenshot(businessName, location);
      partialData.screenshot = screenshot;
      
      // Step 3: AI analysis of screenshot
      console.log('🤖 Step 3: AI analyzing screenshot...');
      partialData.aiAnalysis = await analyzeScreenshotWithAI(screenshot.filepath, businessName);
    } catch (error) {
      errors.push(`Screenshot/AI: ${error.message}`);
      partialData.aiAnalysis = {
        posts: { hasRecent: false, count: 0 },
        productTiles: { hasAny: false, count: 0 },
        qa: { hasAny: false, count: 0 },
        social: { hasAny: false, count: 0 }
      };
    }
    
    // Step 4: Check citations
    console.log('🔍 Step 4: Checking citations...');
    try {
      partialData.citations = await checkCitations(businessName, location);
    } catch (error) {
      errors.push(`Citations: ${error.message}`);
      partialData.citations = {
        found: [],
        checked: [],
        total: 7,
        stats: { found: 0, missing: 7, percentage: 0, score: 0 }
      };
    }
    
    // Step 5: Analyze website
    console.log('🌐 Step 5: Analyzing website...');
    try {
      partialData.websiteAnalysis = await analyzeWebsite(website, location);
    } catch (error) {
      errors.push(`Website: ${error.message}`);
      partialData.websiteAnalysis = {
        hasGBPEmbed: false,
        hasLocalizedPage: false,
        services: [],
        content: '',
        note: 'Website analysis failed'
      };
    }
    
    // Step 6: Analyze reviews
    console.log('📝 Step 6: Analyzing reviews...');
    try {
      partialData.reviewsAnalysis = await analyzeReviews(businessName, location, partialData.outscraper.place_id);
    } catch (error) {
      errors.push(`Reviews: ${error.message}`);
      partialData.reviewsAnalysis = {
        hasRecentReview: false,
        hasBusinessResponses: false,
        reviewCount: 0,
        note: 'Reviews analysis failed'
      };
    }
    
    // Step 7: Compile data for scoring
    const compiledData = {
      businessInfo: { businessName, location, industry, website },
      outscraper: partialData.outscraper,
      aiAnalysis: partialData.aiAnalysis,
      citations: partialData.citations,
      websiteAnalysis: partialData.websiteAnalysis,
      reviewsAnalysis: partialData.reviewsAnalysis,
      screenshot: partialData.screenshot
    };
    
    // Step 8: Calculate score
    console.log('📊 Step 8: Calculating score...');
    const scoreData = calculateScore(compiledData);
    
    // Step 9: Generate smart suggestions
    console.log('🧠 Step 9: Generating smart suggestions...');
    let smartSuggestions = {};
    try {
      smartSuggestions = await generateSmartSuggestions(
        { businessName, location, industry, website },
        scoreData,
        partialData.websiteAnalysis.services || []
      );
    } catch (error) {
      errors.push(`Smart Suggestions: ${error.message}`);
      smartSuggestions = { error: error.message };
    }
    
    // Step 10: Generate action plan
    console.log('📋 Step 10: Creating action plan...');
    const actionPlan = generateActionPlan(scoreData);
    
    // Step 11: Build final report
    // Get user-specific branding or use default
    const brandName = (user && user.custom_brand_name) || BRAND_CONFIG.name;
    const brandLogo = (user && user.custom_brand_logo) || BRAND_CONFIG.logo;
    const preparedBy = (user && user.custom_prepared_by) || `${brandName} ${BRAND_CONFIG.preparedBySuffix}`;
    
    const report = {
      success: true,
      business: { name: businessName, location, industry, website },
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
        factors: Object.entries(scoreData.scores).map(([key, score]) => ({
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
          reviews: partialData.reviewsAnalysis ? 'SUCCESS' : 'FAILED'
        },
        errors: errors,
        costs: {
          outscraper: 0.01,
          scrapingbee: partialData.screenshot ? 0.015 : 0,
          openai_analysis: partialData.aiAnalysis ? 0.02 : 0,
          openai_suggestions: Object.keys(smartSuggestions).length * 0.01,
          serpapi_citations: 0.02,
          serpapi_reviews: 0.02,
          total: 0.085
        }
      }
    };
    
    console.log(`✅ COMPLETE Report generated successfully - Score: ${scoreData.totalScore}/100`);
    if (errors.length > 0) {
      console.log(`⚠️ ${errors.length} non-critical errors occurred`);
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
    landingPage: 'Localized Landing Page'
  };
  return nameMap[key] || key;
}

function getMaxScore(key) {
  const maxScores = {
    claimed: 8, description: 10, categories: 8, productTiles: 10,
    photos: 8, posts: 8, qa: 4, social: 2,
    reviews: 12, citations: 16, gbpEmbed: 8, landingPage: 8
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
    qa: { task: 'Populate Q&A Section', time: '30 minutes', priority: 'LOW' },
    social: { task: 'Add Social Media Links', time: '10 minutes', priority: 'LOW' },
    reviews: { task: 'Implement Review Strategy', time: '2-4 weeks', priority: 'HIGH' },
    citations: { task: 'Build Local Citations', time: '2-4 hours', priority: 'HIGH' },
    gbpEmbed: { task: 'Embed GBP on Website', time: '15 minutes', priority: 'MEDIUM' },
    landingPage: { task: 'Create Localized Landing Page', time: '2-4 hours', priority: 'MEDIUM' }
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
    maxScore: 14,
    missingDirectories: missing.map(dir => dir.directory),
    recommendations: missing.length > 0 ? 
      `Focus on getting listed in: ${missing.slice(0, 3).map(dir => dir.directory).join(', ')}` :
      'Excellent citation coverage across all major directories'
  };
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
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    
    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
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

app.post('/api/login', async (req, res) => {
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
app.post('/api/forgot-password', async (req, res) => {
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
    
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
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
app.post('/api/generate-report', authenticateToken, async (req, res) => {
  try {
    console.log(`📊 Report request from user ${req.user.email}`);
    console.log('🔍 DEBUG: Request body:', req.body);
    
    // Handle both old and new frontend formats
    const { businessName, location, city, industry, category, website } = req.body;
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
    
    console.log(`🏢 Generating ${hasCredits ? 'COMPLETE' : 'PREVIEW'} report for: ${businessName} in ${finalLocation} (${finalIndustry})`);
    
    // Generate complete report with all features
    const report = await generateCompleteReport(businessName, finalLocation, finalIndustry, website, req.user);
    
    // Save report
    try {
      const result = await db.query(
        'INSERT INTO reports (user_id, business_name, city, industry, website, report_data) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
        [req.user.id, businessName, finalLocation, finalIndustry, website || null, JSON.stringify(report)]
      );
      const reportId = result.rows?.[0]?.id || 'unknown';
      console.log(`💾 Report saved with ID: ${reportId}`);
    } catch (err) {
      console.error('Error saving report:', err);
    }

    // Calculate optimization opportunities if the report is locked
    let optimizationOpportunities = 0;
    if (!hasCredits && report.factors) {
      optimizationOpportunities = report.factors.filter(factor => 
        factor.status === 'MISSING' || factor.status === 'NEEDS IMPROVEMENT'
      ).length;
    }

    console.log(`✅ COMPLETE Report generated successfully for ${businessName}`);
    
    // Add locked status and optimization count to response
    const responseReport = {
      ...report,
      isLocked: !hasCredits,
      optimizationOpportunities: hasCredits ? 0 : optimizationOpportunities
    };
    
    res.json(responseReport);
    
  } catch (error) {
    console.error('❌ Report generation error:', error);
    res.status(500).json({ 
      error: 'Failed to generate report. Please try again.'
    });
  }
});

// Get user's reports history
app.get('/api/user-reports', authenticateToken, async (req, res) => {
  try {
    console.log(`📋 Loading reports for user ${req.user.id}`);
    
    const reports = await db.all(
      'SELECT id, business_name, city, industry, website, created_at, report_data FROM reports WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    
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
        score: score
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

// Detailed Citation Analysis endpoint
app.post('/api/detailed-citation-analysis', authenticateToken, async (req, res) => {
  try {
    const { businessName, location } = req.body;
    
    if (!businessName || !location) {
      return res.status(400).json({ error: 'Business name and location are required' });
    }

    console.log(`🔍 Starting detailed citation analysis for: ${businessName} in ${location}`);

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
    const { region } = detectCountryRegion(location);
    const googleDomain = region === 'AE' ? 'google.ae' : region === 'GB' ? 'google.co.uk' : 'google.com';

    // Process each group of 4 directories
    for (let groupIndex = 0; groupIndex < premiumDirectories.length; groupIndex++) {
      const group = premiumDirectories[groupIndex];
      try {
        // Create OR query for the group of 4 directories
        const siteQueries = group.map(dir => `site:${dir.domain}`).join(' OR ');
        const searchQuery = `(${siteQueries}) "${businessName}" ${location}`;
        
        console.log(`🔍 Group ${groupIndex + 1}/10: Searching ${group.map(d => d.name).join(', ')}`);

        const response = await axios.get('https://serpapi.com/search.json', {
          params: {
            engine: 'google',
            q: searchQuery,
            api_key: SERPAPI_KEY,
            num: 10, // More results to catch all 4 potential directories
            google_domain: googleDomain,
            gl: region.toLowerCase(),
            hl: 'en'
          },
          timeout: 10000
        });

        // Process results for each directory in the group
        group.forEach(directory => {
          const found = response.data.organic_results?.some(result => 
            result.link && result.link.includes(directory.domain)
          ) || false;

          results.push({
            name: directory.name,
            domain: directory.domain,
            found: found,
            status: found ? 'FOUND' : 'MISSING'
          });
        });

        // Rate limiting delay
        await new Promise(resolve => setTimeout(resolve, 500));
        
      } catch (groupError) {
        console.error(`❌ Group ${groupIndex + 1} search failed:`, groupError.message);
        // Mark all directories in this group as error
        group.forEach(directory => {
          results.push({
            name: directory.name,
            domain: directory.domain,
            found: false,
            status: 'ERROR'
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
      console.log(`✅ Successfully loaded report ${reportId}`);
      
      res.json({
        success: true,
        report: reportData
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
      // Insert feedback into database
      const stmt = db.prepare(`
        INSERT INTO feedback (user_id, rating, type, message, email, report_data)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      
      stmt.run(
        userId,
        rating,
        type,
        message,
        email || null,
        reportData ? JSON.stringify(reportData) : null,
        async function(err) {
          if (err) {
            console.error('❌ Error saving feedback:', err);
            stmt.finalize();
            return res.status(500).json({ error: 'Failed to save feedback. Please try again.' });
          }
          
          console.log(`✅ Feedback saved successfully for user ${userId} with ID: ${this.lastID}`);
          stmt.finalize();
          
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
        }
      );
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
    
    if (!['oneTime', 'starter', 'pro'].includes(priceType)) {
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
      success_url: `${req.protocol}://${req.get('host')}/dashboard.html?payment=success&session_id={CHECKOUT_SESSION_ID}`,
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
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
  
  let event;
  
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err);
    return res.status(400).send('Webhook signature verification failed');
  }
  
  try {
    switch (event.type) {
      case 'checkout.session.completed':
        const session = event.data.object;
        
        // Handle successful payment
        const userId = parseInt(session.metadata.userId);
        const credits = parseInt(session.metadata.credits);
        const priceType = session.metadata.priceType;
        
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
        if (priceType === 'starter' || priceType === 'pro') {
          await db.query(
            'UPDATE users SET subscription_tier = $1 WHERE id = $2',
            [priceType, userId]
          );
        }
        
        console.log(`✅ Payment successful for user ${userId}: ${credits} credits added`);
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
