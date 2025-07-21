require('dotenv').config();

// Database adapter to support both SQLite and PostgreSQL
class DatabaseAdapter {
  constructor() {
    this.dbType = null;
    this.db = null;
  }

  async initialize() {
    const DATABASE_URL = process.env.DATABASE_URL;
    
    if (DATABASE_URL) {
      // Use PostgreSQL in production
      await this.initializePostgreSQL(DATABASE_URL);
    } else {
      // Use SQLite for local development
      await this.initializeSQLite();
    }
  }

  async initializePostgreSQL(connectionString) {
    const { Pool } = require('pg');
    
    const dbConfig = {
      connectionString,
      ssl: connectionString.includes('localhost') ? false : {
        rejectUnauthorized: false
      }
    };
    
    this.pool = new Pool(dbConfig);
    this.dbType = 'postgresql';
    
    // Test connection
    try {
      await this.pool.query('SELECT NOW()');
      console.log('✅ Connected to PostgreSQL database');
    } catch (err) {
      console.error('❌ PostgreSQL connection failed:', err.message);
      throw err;
    }
  }

  async initializeSQLite() {
    const sqlite3 = require('sqlite3').verbose();
    
    return new Promise((resolve, reject) => {
      this.sqliteDb = new sqlite3.Database('./seo_audit_v3.db', (err) => {
        if (err) {
          console.error('❌ SQLite connection failed:', err.message);
          reject(err);
        } else {
          console.log('✅ Connected to SQLite database (local development)');
          this.dbType = 'sqlite';
          resolve();
        }
      });
    });
  }

  // Convert PostgreSQL style parameters ($1, $2) to SQLite style (?)
  convertQuery(query, dbType) {
    if (dbType === 'sqlite') {
      return query.replace(/\$(\d+)/g, '?');
    }
    return query;
  }

  // Unified query method
  async query(text, params = []) {
    if (this.dbType === 'postgresql') {
      return await this.pool.query(text, params);
    } else {
      // SQLite
      return new Promise((resolve, reject) => {
        const sqliteQuery = this.convertQuery(text, 'sqlite');
        
        if (text.toUpperCase().startsWith('SELECT') || text.toUpperCase().includes('RETURNING')) {
          this.sqliteDb.all(sqliteQuery, params, (err, rows) => {
            if (err) {
              reject(err);
            } else {
              resolve({ rows, rowCount: rows.length });
            }
          });
        } else {
          this.sqliteDb.run(sqliteQuery, params, function(err) {
            if (err) {
              reject(err);
            } else {
              // Simulate PostgreSQL's RETURNING for SQLite
              if (text.toUpperCase().includes('RETURNING')) {
                resolve({ 
                  rows: [{ id: this.lastID }], 
                  rowCount: this.changes 
                });
              } else {
                resolve({ 
                  rows: [], 
                  rowCount: this.changes 
                });
              }
            }
          });
        }
      });
    }
  }

  // Get a single row
  async get(text, params = []) {
    const result = await this.query(text, params);
    return result.rows[0] || null;
  }

  // Get all rows
  async all(text, params = []) {
    const result = await this.query(text, params);
    return result.rows;
  }

  // Run a query (for INSERT, UPDATE, DELETE)
  async run(text, params = []) {
    const result = await this.query(text, params);
    return {
      lastID: result.rows[0]?.id,
      changes: result.rowCount
    };
  }

  // Setup database tables
  async setupTables() {
    if (this.dbType === 'postgresql') {
      await this.setupPostgreSQLTables();
    } else {
      await this.setupSQLiteTables();
    }
  }

  async setupPostgreSQLTables() {
    // Users table
    await this.query(`
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

    // Reports table
    await this.query(`
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

    // Screenshot cache table
    await this.query(`
      CREATE TABLE IF NOT EXISTS screenshot_cache (
        id SERIAL PRIMARY KEY,
        business_name TEXT NOT NULL,
        city TEXT NOT NULL,
        screenshot_filename TEXT NOT NULL,
        screenshot_url TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        file_size INTEGER,
        UNIQUE(business_name, city)
      )
    `);

    // Payments table
    await this.query(`
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

    // Feedback table
    await this.query(`
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
    await this.query('CREATE INDEX IF NOT EXISTS idx_screenshot_cache_expires ON screenshot_cache(expires_at)');
    await this.query('CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id)');
    await this.query('CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id)');
    
    console.log('✅ PostgreSQL tables created/verified');
  }

  async setupSQLiteTables() {
    // Users table
    await this.query(`
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

    // Reports table
    await this.query(`
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

    // Screenshot cache table
    await this.query(`
      CREATE TABLE IF NOT EXISTS screenshot_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        business_name TEXT NOT NULL,
        city TEXT NOT NULL,
        screenshot_filename TEXT NOT NULL,
        screenshot_url TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        file_size INTEGER,
        UNIQUE(business_name, city)
      )
    `);

    // Payments table
    await this.query(`
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

    // Feedback table
    await this.query(`
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

    // Create indexes
    await this.query('CREATE INDEX IF NOT EXISTS idx_screenshot_cache_expires ON screenshot_cache(expires_at)');
    await this.query('CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id)');
    await this.query('CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id)');
    
    console.log('✅ SQLite tables created/verified');
  }
}

module.exports = DatabaseAdapter;