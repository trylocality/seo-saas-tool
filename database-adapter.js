require('dotenv').config();

// Database adapter to support both SQLite and PostgreSQL
class DatabaseAdapter {
  constructor() {
    this.dbType = null;
    this.db = null;
    this.pool = null;
    this.sqliteDb = null;
  }

  async initialize() {
    const DATABASE_URL = process.env.DATABASE_URL;
    
    if (DATABASE_URL) {
      // Use PostgreSQL in production
      console.log('🐘 DATABASE_URL detected, using PostgreSQL');
      await this.initializePostgreSQL(DATABASE_URL);
    } else {
      // Use SQLite for local development
      console.log('📁 No DATABASE_URL, using SQLite for local development');
      await this.initializeSQLite();
    }
  }

  async initializePostgreSQL(connectionString) {
    const { Pool } = require('pg');
    
    console.log('🔍 Initializing PostgreSQL with NODE_ENV:', process.env.NODE_ENV);
    
    // Enhanced configuration for Render PostgreSQL
    const dbConfig = {
      connectionString,
      ssl: process.env.NODE_ENV === 'production' ? {
        rejectUnauthorized: false,
        require: true
      } : false,
      // Connection pool settings for better reliability
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    };
    
    this.pool = new Pool(dbConfig);
    this.dbType = 'postgresql';
    
    console.log('🔍 Database type set to:', this.dbType);
    
    // Test connection with better error handling
    try {
      console.log('🔄 Attempting PostgreSQL connection...');
      const result = await this.pool.query('SELECT NOW()');
      console.log('✅ Connected to PostgreSQL database');
      console.log(`📊 Connection test result: ${result.rows[0].now}`);
    } catch (err) {
      console.error('❌ PostgreSQL connection failed:');
      console.error('Error message:', err.message);
      console.error('Error code:', err.code);
      console.error('Connection string (masked):', connectionString.replace(/:[^:@]*@/, ':***@'));
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
    // Validate query
    if (!text || typeof text !== 'string' || text.trim() === '') {
      throw new Error('Invalid query: query text is empty or not a string');
    }
    
    if (this.dbType === 'postgresql') {
      // IMPORTANT: PostgreSQL queries should NOT be converted
      if (text.includes('?')) {
        console.error('⚠️ WARNING: PostgreSQL query contains SQLite-style placeholder: ?');
        console.error('Query:', text);
        // Auto-fix the query
        let fixedQuery = text;
        let paramIndex = 1;
        while (fixedQuery.includes('?')) {
          fixedQuery = fixedQuery.replace('?', '$' + paramIndex);
          paramIndex++;
        }
        console.log('Auto-fixed to:', fixedQuery);
        text = fixedQuery;
      }
      
      try {
        return await this.pool.query(text, params);
      } catch (err) {
        console.error('PostgreSQL query error:');
        console.error('Query:', text);
        console.error('Params:', params);
        console.error('Error:', err);
        throw err;
      }
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
    // Ensure text is a valid string
    if (!text || typeof text !== 'string') {
      throw new Error(`Invalid query text in get(): ${JSON.stringify(text)}`);
    }
    
    // CRITICAL FIX: If we're using PostgreSQL and the query has been incorrectly converted to SQLite style,
    // convert it back to PostgreSQL style
    if (this.dbType === 'postgresql' && text.includes('?')) {
      console.warn('⚠️ Fixing incorrectly converted query for PostgreSQL');
      let fixedQuery = text;
      let paramIndex = 1;
      while (fixedQuery.includes('?')) {
        fixedQuery = fixedQuery.replace('?', '$' + paramIndex);
        paramIndex++;
      }
      console.log(`Fixed query: "${fixedQuery}"`);
      text = fixedQuery;
    }
    
    try {
      const result = await this.query(text, params);
      return result.rows[0] || null;
    } catch (err) {
      console.error('Error in get() method:');
      console.error('Query text:', text);
      console.error('Params:', params);
      throw err;
    }
  }

  // Get all rows
  async all(text, params = []) {
    // Ensure text is a valid string
    if (!text || typeof text !== 'string') {
      throw new Error(`Invalid query text in all(): ${JSON.stringify(text)}`);
    }
    
    // CRITICAL FIX: If we're using PostgreSQL and the query has been incorrectly converted to SQLite style,
    // convert it back to PostgreSQL style
    if (this.dbType === 'postgresql' && text.includes('?')) {
      console.warn('⚠️ Fixing incorrectly converted query for PostgreSQL in all()');
      let fixedQuery = text;
      let paramIndex = 1;
      while (fixedQuery.includes('?')) {
        fixedQuery = fixedQuery.replace('?', '$' + paramIndex);
        paramIndex++;
      }
      text = fixedQuery;
    }
    
    try {
      const result = await this.query(text, params);
      return result.rows;
    } catch (err) {
      console.error('Error in all() method:');
      console.error('Query text:', text);
      console.error('Params:', params);
      throw err;
    }
  }

  // Run a query (for INSERT, UPDATE, DELETE)
  async run(text, params = []) {
    // Ensure text is a valid string
    if (!text || typeof text !== 'string') {
      throw new Error(`Invalid query text in run(): ${JSON.stringify(text)}`);
    }
    
    // CRITICAL FIX: If we're using PostgreSQL and the query has been incorrectly converted to SQLite style,
    // convert it back to PostgreSQL style
    if (this.dbType === 'postgresql' && text.includes('?')) {
      console.warn('⚠️ Fixing incorrectly converted query for PostgreSQL in run()');
      let fixedQuery = text;
      let paramIndex = 1;
      while (fixedQuery.includes('?')) {
        fixedQuery = fixedQuery.replace('?', '$' + paramIndex);
        paramIndex++;
      }
      text = fixedQuery;
    }
    
    try {
      const result = await this.query(text, params);
      return {
        lastID: result.rows[0]?.id,
        changes: result.rowCount
      };
    } catch (err) {
      console.error('Error in run() method:');
      console.error('Query text:', text);
      console.error('Params:', params);
      throw err;
    }
  }

  // Setup database tables
  async setupTables() {
    if (this.dbType === 'postgresql') {
      await this.setupPostgreSQLTables();
      await this.runPostgreSQLMigrations();
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
        custom_primary_color TEXT DEFAULT NULL,
        custom_contact_name TEXT DEFAULT NULL,
        custom_contact_email TEXT DEFAULT NULL,
        custom_contact_phone TEXT DEFAULT NULL,
        white_label_enabled BOOLEAN DEFAULT FALSE,
        email_verified BOOLEAN DEFAULT FALSE,
        email_verification_token TEXT DEFAULT NULL,
        email_verification_expires TIMESTAMP DEFAULT NULL,
        password_reset_token TEXT DEFAULT NULL,
        password_reset_expires TIMESTAMP DEFAULT NULL,
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
        was_paid BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Screenshot cache table
    try {
      await this.query(`
        CREATE TABLE IF NOT EXISTS screenshot_cache (
          id SERIAL PRIMARY KEY,
          cache_key TEXT UNIQUE NOT NULL,
          filepath TEXT NOT NULL,
          filename TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          expires_at TIMESTAMP NOT NULL
        )
      `);
      console.log('✅ screenshot_cache table ready');
    } catch (error) {
      console.log(`⚠️ screenshot_cache table warning: ${error.message}`);
    }

    // API cache table for Outscraper and other API results
    try {
      await this.query(`
        CREATE TABLE IF NOT EXISTS api_cache (
          id SERIAL PRIMARY KEY,
          cache_key TEXT UNIQUE NOT NULL,
          data JSONB NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          expires_at TIMESTAMP NOT NULL
        )
      `);
      console.log('✅ api_cache table ready');
    } catch (error) {
      console.log(`⚠️ api_cache table warning: ${error.message}`);
    }

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

    // AppSumo codes table
    await this.query(`
      CREATE TABLE IF NOT EXISTS appsumo_codes (
        id SERIAL PRIMARY KEY,
        code TEXT UNIQUE NOT NULL,
        plan_id TEXT NOT NULL,
        plan_name TEXT NOT NULL,
        monthly_credits INTEGER NOT NULL,
        is_redeemed BOOLEAN DEFAULT FALSE,
        redeemed_by_user_id INTEGER REFERENCES users(id),
        redeemed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create indexes for performance (with error handling for missing tables)
    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_screenshot_cache_expires ON screenshot_cache(expires_at)',
      'CREATE INDEX IF NOT EXISTS idx_screenshot_cache_key ON screenshot_cache(cache_key)',
      'CREATE INDEX IF NOT EXISTS idx_api_cache_expires ON api_cache(expires_at)',
      'CREATE INDEX IF NOT EXISTS idx_api_cache_key ON api_cache(cache_key)',
      'CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
      'CREATE INDEX IF NOT EXISTS idx_users_verification_token ON users(email_verification_token)',
      'CREATE INDEX IF NOT EXISTS idx_users_reset_token ON users(password_reset_token)',
      'CREATE INDEX IF NOT EXISTS idx_payments_session_id ON payments(stripe_session_id)',
      'CREATE INDEX IF NOT EXISTS idx_payments_created_at ON payments(created_at DESC)',
      'CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at DESC)',
      'CREATE INDEX IF NOT EXISTS idx_reports_was_paid ON reports(was_paid)',
      'CREATE INDEX IF NOT EXISTS idx_feedback_user_id ON feedback(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_appsumo_codes_code ON appsumo_codes(code)',
      'CREATE INDEX IF NOT EXISTS idx_appsumo_codes_redeemed ON appsumo_codes(is_redeemed)'
    ];

    for (const indexQuery of indexes) {
      try {
        await this.query(indexQuery);
      } catch (error) {
        // Silently skip if table/column doesn't exist (will be created on next deployment)
        console.log(`⚠️ Skipped index: ${error.message}`);
      }
    }

    // Add new columns if they don't exist (for existing databases)
    const columnsToAdd = [
      { name: 'email_verified', definition: 'BOOLEAN DEFAULT FALSE' },
      { name: 'email_verification_token', definition: 'TEXT DEFAULT NULL' },
      { name: 'email_verification_expires', definition: 'TIMESTAMP DEFAULT NULL' },
      { name: 'password_reset_token', definition: 'TEXT DEFAULT NULL' },
      { name: 'password_reset_expires', definition: 'TIMESTAMP DEFAULT NULL' },
      { name: 'custom_primary_color', definition: 'TEXT DEFAULT NULL' },
      { name: 'custom_contact_name', definition: 'TEXT DEFAULT NULL' },
      { name: 'custom_contact_email', definition: 'TEXT DEFAULT NULL' },
      { name: 'custom_contact_phone', definition: 'TEXT DEFAULT NULL' },
      { name: 'white_label_enabled', definition: 'BOOLEAN DEFAULT FALSE' },
      { name: 'appsumo_code', definition: 'TEXT DEFAULT NULL' },
      { name: 'appsumo_plan_id', definition: 'TEXT DEFAULT NULL' },
      { name: 'is_lifetime', definition: 'BOOLEAN DEFAULT FALSE' },
      { name: 'lifetime_monthly_credits', definition: 'INTEGER DEFAULT NULL' },
      { name: 'last_credit_renewal', definition: 'TIMESTAMP DEFAULT NULL' }
    ];

    for (const column of columnsToAdd) {
      try {
        // Check if column exists first
        const columnCheck = await this.query(`
          SELECT column_name 
          FROM information_schema.columns 
          WHERE table_name = 'users' AND column_name = $1
        `, [column.name]);
        
        if (columnCheck.length === 0) {
          await this.query(`ALTER TABLE users ADD COLUMN ${column.name} ${column.definition}`);
          console.log(`✅ Added column: ${column.name}`);
        }
      } catch (e) {
        console.warn(`⚠️ Column ${column.name} setup skipped:`, e.message);
      }
    }

    // Add was_paid column to reports table if it doesn't exist
    try {
      const reportColumnCheck = await this.query(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = 'reports' AND column_name = 'was_paid'
      `);
      
      if (reportColumnCheck.length === 0) {
        await this.query(`ALTER TABLE reports ADD COLUMN was_paid BOOLEAN DEFAULT FALSE`);
        console.log(`✅ Added was_paid column to reports table`);
      }
    } catch (e) {
      console.log(`⚠️ Reports was_paid column setup skipped: ${e.message}`);
    }

    // Add detailed_citation_analysis column to reports table if it doesn't exist
    try {
      const detailedColumnCheck = await this.query(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = 'reports' AND column_name = 'detailed_citation_analysis'
      `);
      
      if (detailedColumnCheck.length === 0) {
        await this.query(`ALTER TABLE reports ADD COLUMN detailed_citation_analysis TEXT DEFAULT NULL`);
        console.log(`✅ Added detailed_citation_analysis column to reports table`);
      }
    } catch (e) {
      console.log(`⚠️ Reports detailed_citation_analysis column setup skipped: ${e.message}`);
    }
    
    console.log('✅ PostgreSQL tables created/verified');
  }

  async runPostgreSQLMigrations() {
    console.log('🔄 Running PostgreSQL migrations...');

    // Migration 1: Add was_paid column to reports table if it doesn't exist
    try {
      await this.query(`
        ALTER TABLE reports
        ADD COLUMN IF NOT EXISTS was_paid BOOLEAN DEFAULT FALSE
      `);
      console.log('✅ Migration: was_paid column added to reports table');
    } catch (error) {
      if (error.message.includes('already exists')) {
        console.log('✅ Migration: was_paid column already exists');
      } else {
        console.log(`⚠️ Migration warning (was_paid): ${error.message}`);
      }
    }

    // Migration 2: Create screenshot_cache table if it doesn't exist
    try {
      await this.query(`
        CREATE TABLE IF NOT EXISTS screenshot_cache (
          id SERIAL PRIMARY KEY,
          cache_key TEXT UNIQUE NOT NULL,
          filepath TEXT NOT NULL,
          filename TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          expires_at TIMESTAMP NOT NULL
        )
      `);
      console.log('✅ Migration: screenshot_cache table created');
    } catch (error) {
      console.log(`⚠️ Migration warning (screenshot_cache): ${error.message}`);
    }

    // Migration 3: Create api_cache table if it doesn't exist
    try {
      await this.query(`
        CREATE TABLE IF NOT EXISTS api_cache (
          id SERIAL PRIMARY KEY,
          cache_key TEXT UNIQUE NOT NULL,
          data JSONB NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          expires_at TIMESTAMP NOT NULL
        )
      `);
      console.log('✅ Migration: api_cache table created');
    } catch (error) {
      console.log(`⚠️ Migration warning (api_cache): ${error.message}`);
    }

    // Migration 4: Create appsumo_codes table if it doesn't exist
    try {
      await this.query(`
        CREATE TABLE IF NOT EXISTS appsumo_codes (
          id SERIAL PRIMARY KEY,
          code TEXT UNIQUE NOT NULL,
          plan_id TEXT NOT NULL,
          plan_name TEXT NOT NULL,
          monthly_credits INTEGER NOT NULL,
          is_redeemed BOOLEAN DEFAULT FALSE,
          redeemed_by_user_id INTEGER REFERENCES users(id),
          redeemed_at TIMESTAMP,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      console.log('✅ Migration: appsumo_codes table created');
    } catch (error) {
      console.log(`⚠️ Migration warning (appsumo_codes): ${error.message}`);
    }

    // Migration 5: Add AppSumo columns to users table
    const appsumoColumns = [
      { name: 'appsumo_code', type: 'TEXT DEFAULT NULL' },
      { name: 'appsumo_plan_id', type: 'TEXT DEFAULT NULL' },
      { name: 'is_lifetime', type: 'BOOLEAN DEFAULT FALSE' },
      { name: 'lifetime_monthly_credits', type: 'INTEGER DEFAULT NULL' },
      { name: 'last_credit_renewal', type: 'TIMESTAMP DEFAULT NULL' }
    ];

    for (const col of appsumoColumns) {
      try {
        await this.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS ${col.name} ${col.type}`);
        console.log(`✅ Migration: Added ${col.name} column to users table`);
      } catch (error) {
        console.log(`⚠️ Migration warning (${col.name}): ${error.message}`);
      }
    }

    // Migration 6: Fix screenshot_cache table schema (drop and recreate with correct columns)
    try {
      // Check if the table has the wrong schema
      const columns = await this.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'screenshot_cache'
      `);

      const columnNames = columns.rows.map(row => row.column_name);
      const hasCorrectSchema = columnNames.includes('cache_key') && columnNames.includes('filepath');

      if (!hasCorrectSchema) {
        console.log('🔧 Migration: Fixing screenshot_cache table schema...');

        // Drop old table (losing cache is OK, it will regenerate)
        await this.query('DROP TABLE IF EXISTS screenshot_cache CASCADE');
        console.log('✅ Dropped old screenshot_cache table with incorrect schema');

        // Recreate with correct schema
        await this.query(`
          CREATE TABLE screenshot_cache (
            id SERIAL PRIMARY KEY,
            cache_key TEXT UNIQUE NOT NULL,
            filepath TEXT NOT NULL,
            filename TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL
          )
        `);
        console.log('✅ Created screenshot_cache table with correct schema');

        // Recreate indexes
        await this.query('CREATE INDEX IF NOT EXISTS idx_screenshot_cache_expires ON screenshot_cache(expires_at)');
        await this.query('CREATE INDEX IF NOT EXISTS idx_screenshot_cache_key ON screenshot_cache(cache_key)');
        console.log('✅ Created indexes on screenshot_cache table');
      } else {
        console.log('✅ Migration: screenshot_cache table already has correct schema');
      }
    } catch (error) {
      console.log(`⚠️ Migration warning (screenshot_cache schema fix): ${error.message}`);
    }

    // Future migrations can be added here
    console.log('✅ All PostgreSQL migrations completed');
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
        custom_primary_color TEXT DEFAULT NULL,
        custom_contact_name TEXT DEFAULT NULL,
        custom_contact_email TEXT DEFAULT NULL,
        custom_contact_phone TEXT DEFAULT NULL,
        white_label_enabled BOOLEAN DEFAULT FALSE,
        email_verified INTEGER DEFAULT 0,
        email_verification_token TEXT DEFAULT NULL,
        email_verification_expires DATETIME DEFAULT NULL,
        password_reset_token TEXT DEFAULT NULL,
        password_reset_expires DATETIME DEFAULT NULL,
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
        was_paid INTEGER DEFAULT 0,
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

    // Add new columns if they don't exist (for existing databases) - MUST happen before creating indexes on these columns
    const columnsToAdd = [
      { name: 'email_verified', definition: 'INTEGER DEFAULT 0' },
      { name: 'email_verification_token', definition: 'TEXT DEFAULT NULL' },
      { name: 'email_verification_expires', definition: 'DATETIME DEFAULT NULL' },
      { name: 'password_reset_token', definition: 'TEXT DEFAULT NULL' },
      { name: 'password_reset_expires', definition: 'DATETIME DEFAULT NULL' },
      { name: 'custom_primary_color', definition: 'TEXT DEFAULT NULL' },
      { name: 'custom_contact_name', definition: 'TEXT DEFAULT NULL' },
      { name: 'custom_contact_email', definition: 'TEXT DEFAULT NULL' },
      { name: 'custom_contact_phone', definition: 'TEXT DEFAULT NULL' },
      { name: 'white_label_enabled', definition: 'INTEGER DEFAULT 0' }
    ];

    for (const column of columnsToAdd) {
      try {
        // Check if column exists first using PRAGMA table_info
        const columnCheck = await this.query('PRAGMA table_info(users)');
        const columnExists = columnCheck.some(col => col.name === column.name);
        
        if (!columnExists) {
          await this.query(`ALTER TABLE users ADD COLUMN ${column.name} ${column.definition}`);
          console.log(`✅ Added column: ${column.name}`);
        }
      } catch (e) {
        console.warn(`⚠️ Column ${column.name} setup skipped:`, e.message);
      }
    }

    // Add was_paid column to reports table if it doesn't exist
    try {
      const reportColumnCheck = await this.query('PRAGMA table_info(reports)');
      const columnExists = reportColumnCheck.some(col => col.name === 'was_paid');
      
      if (!columnExists) {
        await this.query(`ALTER TABLE reports ADD COLUMN was_paid INTEGER DEFAULT 0`);
        console.log(`✅ Added was_paid column to reports table`);
      }
    } catch (e) {
      console.log(`⚠️ Reports was_paid column setup skipped: ${e.message}`);
    }

    // Add detailed_citation_analysis column to reports table if it doesn't exist
    try {
      const reportColumnCheck = await this.query('PRAGMA table_info(reports)');
      const detailedColumnExists = reportColumnCheck.some(col => col.name === 'detailed_citation_analysis');
      
      if (!detailedColumnExists) {
        await this.query(`ALTER TABLE reports ADD COLUMN detailed_citation_analysis TEXT DEFAULT NULL`);
        console.log(`✅ Added detailed_citation_analysis column to reports table`);
      }
    } catch (e) {
      console.log(`⚠️ Reports detailed_citation_analysis column setup skipped: ${e.message}`);
    }

    // Create indexes for performance - MUST happen after columns are added
    // Wrap each in try-catch to prevent one failure from stopping all index creation
    const indexes = [
      { name: 'idx_screenshot_cache_expires', table: 'screenshot_cache', column: 'expires_at' },
      { name: 'idx_reports_user_id', table: 'reports', column: 'user_id' },
      { name: 'idx_payments_user_id', table: 'payments', column: 'user_id' },
      { name: 'idx_users_email', table: 'users', column: 'email' },
      { name: 'idx_users_verification_token', table: 'users', column: 'email_verification_token' },
      { name: 'idx_users_reset_token', table: 'users', column: 'password_reset_token' },
      { name: 'idx_payments_session_id', table: 'payments', column: 'stripe_session_id' },
      { name: 'idx_payments_created_at', table: 'payments', column: 'created_at DESC' },
      { name: 'idx_reports_created_at', table: 'reports', column: 'created_at DESC' },
      { name: 'idx_reports_was_paid', table: 'reports', column: 'was_paid' },
      { name: 'idx_feedback_user_id', table: 'feedback', column: 'user_id' }
    ];

    for (const index of indexes) {
      try {
        await this.query(`CREATE INDEX IF NOT EXISTS ${index.name} ON ${index.table}(${index.column})`);
      } catch (e) {
        console.warn(`⚠️ Could not create index ${index.name}:`, e.message);
      }
    }

    console.log('✅ SQLite tables created/verified');
  }
}

module.exports = DatabaseAdapter;