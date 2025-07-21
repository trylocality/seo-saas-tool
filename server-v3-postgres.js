require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const axios = require('axios');
const fs = require('fs').promises;
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const https = require('https');
const querystring = require('querystring');

// ==========================================
// DATABASE CONFIGURATION
// ==========================================

// Determine which database to use based on environment
const DATABASE_URL = process.env.DATABASE_URL;
const isProduction = DATABASE_URL ? true : false;

let db;
let dbType;

if (isProduction) {
  // PostgreSQL for production
  const { Pool } = require('pg');
  
  // Parse DATABASE_URL for SSL requirements
  const dbConfig = {
    connectionString: DATABASE_URL,
    ssl: DATABASE_URL.includes('localhost') ? false : {
      rejectUnauthorized: false
    }
  };
  
  db = new Pool(dbConfig);
  dbType = 'postgresql';
  
  console.log('🐘 Connecting to PostgreSQL database...');
  
  // Test connection
  db.query('SELECT NOW()', (err, res) => {
    if (err) {
      console.error('❌ PostgreSQL connection failed:', err.message);
      process.exit(1);
    }
    console.log('✅ Connected to PostgreSQL database');
  });
} else {
  // SQLite for local development
  const sqlite3 = require('sqlite3').verbose();
  const sqlite = new sqlite3.Database('./seo_audit_v3.db', (err) => {
    if (err) {
      console.error('❌ SQLite connection failed:', err.message);
      process.exit(1);
    }
    console.log('✅ Connected to SQLite database (local development)');
  });
  
  // Wrap SQLite to match PostgreSQL interface
  db = {
    query: (text, params) => {
      return new Promise((resolve, reject) => {
        // Convert PostgreSQL placeholders ($1, $2) to SQLite (?)
        const sqliteQuery = text.replace(/\$(\d+)/g, '?');
        
        if (text.toUpperCase().startsWith('SELECT') || text.toUpperCase().includes('RETURNING')) {
          sqlite.all(sqliteQuery, params || [], (err, rows) => {
            if (err) reject(err);
            else resolve({ rows });
          });
        } else {
          sqlite.run(sqliteQuery, params || [], function(err) {
            if (err) reject(err);
            else resolve({ rows: [{ id: this.lastID }], rowCount: this.changes });
          });
        }
      });
    }
  };
  dbType = 'sqlite';
}

// ==========================================
// CONFIGURATION & ENVIRONMENT VARIABLES
// ==========================================

const app = express();
const PORT = process.env.PORT || 3000;

// API Keys - Set these in your environment
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-this-123456789';
const OUTSCRAPER_API_KEY = process.env.OUTSCRAPER_API_KEY;
const SCRAPINGBEE_API_KEY = process.env.SCRAPINGBEE_API_KEY;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const SERPAPI_KEY = process.env.SERPAPI_KEY;

// Stripe Configuration
const STRIPE_PRICES = {
  oneTime: process.env.STRIPE_PRICE_ONE_TIME || 'price_1ReQIIDEq7s1BPEYZfi9Nk6C',
  starter: process.env.STRIPE_PRICE_STARTER || 'price_1ReQPvDEq7s1BPEYDbR6A3IJ',
  pro: process.env.STRIPE_PRICE_PRO || 'price_1ReR1MDEq7s1BPEYHzSW0uTn'
};

const CREDIT_AMOUNTS = {
  oneTime: 1,
  starter: 10,
  pro: 50
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
// DATABASE SCHEMA SETUP
// ==========================================

async function setupDatabase() {
  try {
    if (dbType === 'postgresql') {
      // PostgreSQL table creation
      await db.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          first_name TEXT NOT NULL,
          last_name TEXT NOT NULL,
          credits_remaining INTEGER DEFAULT 1,
          subscription_tier TEXT DEFAULT 'free',
          custom_brand_name TEXT DEFAULT NULL,
          custom_brand_logo TEXT DEFAULT NULL,
          custom_prepared_by TEXT DEFAULT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);

      await db.query(`
        CREATE TABLE IF NOT EXISTS reports (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id),
          business_name TEXT NOT NULL,
          city TEXT NOT NULL,
          industry TEXT NOT NULL,
          website TEXT,
          report_data TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);

      await db.query(`
        CREATE TABLE IF NOT EXISTS screenshot_cache (
          id SERIAL PRIMARY KEY,
          business_name TEXT NOT NULL,
          screenshot_url TEXT NOT NULL,
          expiry_date TIMESTAMP NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);

      await db.query(`
        CREATE TABLE IF NOT EXISTS payments (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id),
          stripe_session_id TEXT UNIQUE NOT NULL,
          stripe_payment_intent_id TEXT,
          amount INTEGER NOT NULL,
          currency TEXT DEFAULT 'usd',
          status TEXT NOT NULL,
          product_type TEXT NOT NULL,
          credits_purchased INTEGER NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);

      await db.query(`
        CREATE TABLE IF NOT EXISTS feedback (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id),
          rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
          feedback_type TEXT NOT NULL,
          message TEXT NOT NULL,
          user_email TEXT,
          report_data TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Create indexes
      await db.query('CREATE INDEX IF NOT EXISTS idx_screenshot_cache_expiry ON screenshot_cache(expiry_date)');
      await db.query('CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id)');
      await db.query('CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id)');
      
    } else {
      // SQLite table creation (existing code)
      const sqlite3 = require('sqlite3').verbose();
      const sqlite = new sqlite3.Database('./seo_audit_v3.db');
      
      await new Promise((resolve) => {
        sqlite.serialize(() => {
          sqlite.run(`
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              email TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              first_name TEXT NOT NULL,
              last_name TEXT NOT NULL,
              credits_remaining INTEGER DEFAULT 1,
              subscription_tier TEXT DEFAULT 'free',
              custom_brand_name TEXT DEFAULT NULL,
              custom_brand_logo TEXT DEFAULT NULL,
              custom_prepared_by TEXT DEFAULT NULL,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
          `);

          sqlite.run(`
            CREATE TABLE IF NOT EXISTS reports (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              business_name TEXT NOT NULL,
              city TEXT NOT NULL,
              industry TEXT NOT NULL,
              website TEXT,
              report_data TEXT NOT NULL,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY (user_id) REFERENCES users (id)
            )
          `);

          sqlite.run(`
            CREATE TABLE IF NOT EXISTS screenshot_cache (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              business_name TEXT NOT NULL,
              screenshot_url TEXT NOT NULL,
              expiry_date DATETIME NOT NULL,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
          `);

          sqlite.run(`
            CREATE TABLE IF NOT EXISTS payments (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              stripe_session_id TEXT UNIQUE NOT NULL,
              stripe_payment_intent_id TEXT,
              amount INTEGER NOT NULL,
              currency TEXT DEFAULT 'usd',
              status TEXT NOT NULL,
              product_type TEXT NOT NULL,
              credits_purchased INTEGER NOT NULL,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY (user_id) REFERENCES users (id)
            )
          `);

          sqlite.run(`
            CREATE TABLE IF NOT EXISTS feedback (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER,
              rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
              feedback_type TEXT NOT NULL,
              message TEXT NOT NULL,
              user_email TEXT,
              report_data TEXT,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY (user_id) REFERENCES users (id)
            )
          `);

          sqlite.run('CREATE INDEX IF NOT EXISTS idx_screenshot_cache_expiry ON screenshot_cache(expiry_date)');
          sqlite.run('CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id)');
          sqlite.run('CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id)', resolve);
        });
      });
    }
    
    console.log('✅ Database tables created/verified');
  } catch (err) {
    console.error('❌ Error setting up database:', err);
    process.exit(1);
  }
}

// Initialize database
setupDatabase();

// ==========================================
// MIDDLEWARE SETUP
// ==========================================

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(403).json({ message: 'No token provided' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }
    req.userId = decoded.userId;
    next();
  });
}

// ==========================================
// AUTHENTICATION ENDPOINTS
// ==========================================

// Sign up endpoint
app.post('/api/signup', async (req, res) => {
  const { email, password, firstName, lastName } = req.body;
  
  try {
    // Check if user already exists
    const existingUser = await db.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: 'Email already registered' });
    }
    
    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Insert new user
    const result = await db.query(
      'INSERT INTO users (email, password_hash, first_name, last_name) VALUES ($1, $2, $3, $4) RETURNING id',
      [email, passwordHash, firstName, lastName]
    );
    
    const userId = result.rows[0].id;
    
    // Generate JWT token
    const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ 
      message: 'Account created successfully', 
      token,
      user: {
        id: userId,
        email,
        firstName,
        lastName,
        credits: 1
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Error creating account' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    // Get user from database
    const result = await db.query(
      'SELECT id, email, password_hash, first_name, last_name, credits_remaining FROM users WHERE email = $1',
      [email]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    const user = result.rows[0];
    
    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    // Generate JWT token
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ 
      message: 'Login successful', 
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        credits: user.credits_remaining
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Get user profile
app.get('/api/user/profile', verifyToken, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, email, first_name, last_name, credits_remaining, subscription_tier FROM users WHERE id = $1',
      [req.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const user = result.rows[0];
    
    res.json({
      id: user.id,
      email: user.email,
      firstName: user.first_name,
      lastName: user.last_name,
      credits: user.credits_remaining,
      subscriptionTier: user.subscription_tier
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ message: 'Error fetching profile' });
  }
});

// ==========================================
// REPORT ENDPOINTS
// ==========================================

// Get user's reports
app.get('/api/reports', verifyToken, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM reports WHERE user_id = $1 ORDER BY created_at DESC',
      [req.userId]
    );
    
    const reports = result.rows.map(report => ({
      ...report,
      report_data: JSON.parse(report.report_data)
    }));
    
    res.json(reports);
  } catch (error) {
    console.error('Error fetching reports:', error);
    res.status(500).json({ message: 'Error fetching reports' });
  }
});

// ==========================================
// Continue with the rest of the endpoints...
// ==========================================

// Note: The rest of the file continues with the same pattern of converting queries
// I'll include the key parts that need modification for PostgreSQL compatibility