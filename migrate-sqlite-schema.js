/**
 * SQLite Database Migration Script
 * Adds missing columns to match PostgreSQL schema
 * Safe to run multiple times (idempotent)
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = path.join(__dirname, 'seo_audit_v3.db');

console.log('🔧 Starting SQLite database migration...\n');

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('❌ Failed to connect to database:', err);
    process.exit(1);
  }
  console.log('✅ Connected to SQLite database\n');
});

// Helper function to check if column exists
function columnExists(tableName, columnName) {
  return new Promise((resolve, reject) => {
    db.all(`PRAGMA table_info(${tableName})`, (err, rows) => {
      if (err) reject(err);
      else resolve(rows.some(row => row.name === columnName));
    });
  });
}

// Helper function to add column if it doesn't exist
async function addColumnIfMissing(tableName, columnName, columnDefinition) {
  const exists = await columnExists(tableName, columnName);
  if (exists) {
    console.log(`   ⏭️  Column '${columnName}' already exists in '${tableName}'`);
    return false;
  }

  return new Promise((resolve, reject) => {
    db.run(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnDefinition}`, (err) => {
      if (err) {
        console.error(`   ❌ Failed to add '${columnName}': ${err.message}`);
        reject(err);
      } else {
        console.log(`   ✅ Added column '${columnName}' to '${tableName}'`);
        resolve(true);
      }
    });
  });
}

// Migration steps
async function migrate() {
  try {
    console.log('📋 Step 1: Migrating USERS table...');

    // Email verification columns
    await addColumnIfMissing('users', 'email_verified', 'INTEGER DEFAULT 0');
    await addColumnIfMissing('users', 'email_verification_token', 'TEXT DEFAULT NULL');
    await addColumnIfMissing('users', 'email_verification_expires', 'DATETIME DEFAULT NULL');

    // Password reset columns
    await addColumnIfMissing('users', 'password_reset_token', 'TEXT DEFAULT NULL');
    await addColumnIfMissing('users', 'password_reset_expires', 'DATETIME DEFAULT NULL');

    // White label columns
    await addColumnIfMissing('users', 'custom_primary_color', 'TEXT DEFAULT NULL');
    await addColumnIfMissing('users', 'custom_contact_name', 'TEXT DEFAULT NULL');
    await addColumnIfMissing('users', 'custom_contact_email', 'TEXT DEFAULT NULL');
    await addColumnIfMissing('users', 'custom_contact_phone', 'TEXT DEFAULT NULL');
    await addColumnIfMissing('users', 'white_label_enabled', 'INTEGER DEFAULT 0');

    // AppSumo columns
    await addColumnIfMissing('users', 'appsumo_code', 'TEXT DEFAULT NULL');
    await addColumnIfMissing('users', 'appsumo_plan_id', 'TEXT DEFAULT NULL');
    await addColumnIfMissing('users', 'is_lifetime', 'INTEGER DEFAULT 0');
    await addColumnIfMissing('users', 'lifetime_monthly_credits', 'INTEGER DEFAULT NULL');
    await addColumnIfMissing('users', 'last_credit_renewal', 'DATETIME DEFAULT NULL');

    console.log('\n📋 Step 2: Migrating PAYMENTS table...');

    // Payment columns - CRITICAL for Stripe webhooks
    await addColumnIfMissing('payments', 'stripe_session_id', 'TEXT DEFAULT NULL');
    await addColumnIfMissing('payments', 'stripe_payment_intent_id', 'TEXT DEFAULT NULL');
    await addColumnIfMissing('payments', 'product_type', 'TEXT DEFAULT NULL');
    await addColumnIfMissing('payments', 'currency', 'TEXT DEFAULT "usd"');

    console.log('\n📋 Step 3: Migrating REPORTS table...');

    // Reports columns
    await addColumnIfMissing('reports', 'was_paid', 'INTEGER DEFAULT 0');

    console.log('\n📋 Step 4: Creating indexes for performance...');

    // Create indexes (ignore errors if they already exist)
    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_users_verification_token ON users(email_verification_token)',
      'CREATE INDEX IF NOT EXISTS idx_users_reset_token ON users(password_reset_token)',
      'CREATE INDEX IF NOT EXISTS idx_users_email_verified ON users(email_verified)',
      'CREATE INDEX IF NOT EXISTS idx_payments_stripe_session ON payments(stripe_session_id)',
      'CREATE INDEX IF NOT EXISTS idx_payments_product_type ON payments(product_type)',
      'CREATE INDEX IF NOT EXISTS idx_reports_was_paid ON reports(was_paid)',
      'CREATE INDEX IF NOT EXISTS idx_users_appsumo_code ON users(appsumo_code)',
      'CREATE INDEX IF NOT EXISTS idx_users_is_lifetime ON users(is_lifetime)'
    ];

    for (const indexSQL of indexes) {
      await new Promise((resolve, reject) => {
        db.run(indexSQL, (err) => {
          if (err) {
            console.log(`   ⚠️  Index may already exist: ${err.message.split(':')[0]}`);
          } else {
            const indexName = indexSQL.match(/idx_\w+/)?.[0] || 'index';
            console.log(`   ✅ Created index: ${indexName}`);
          }
          resolve(); // Continue even if index exists
        });
      });
    }

    console.log('\n📋 Step 5: Adding unique constraint to stripe_session_id...');

    // Check if we need to recreate payments table with unique constraint
    const hasUniqueConstraint = await new Promise((resolve) => {
      db.get(`SELECT sql FROM sqlite_master WHERE type='table' AND name='payments'`, (err, row) => {
        if (err || !row) resolve(false);
        else resolve(row.sql.includes('UNIQUE') && row.sql.includes('stripe_session_id'));
      });
    });

    if (!hasUniqueConstraint) {
      console.log('   🔄 Adding UNIQUE constraint to stripe_session_id...');

      // SQLite doesn't support adding constraints to existing tables
      // We need to create a new table and copy data
      await new Promise((resolve, reject) => {
        db.serialize(() => {
          db.run('BEGIN TRANSACTION');

          // Create new table with correct schema
          db.run(`
            CREATE TABLE payments_new (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              amount INTEGER NOT NULL,
              credits_purchased INTEGER NOT NULL,
              stripe_payment_id TEXT,
              status TEXT DEFAULT 'pending',
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              stripe_session_id TEXT UNIQUE,
              stripe_payment_intent_id TEXT,
              product_type TEXT,
              currency TEXT DEFAULT 'usd',
              FOREIGN KEY (user_id) REFERENCES users (id)
            )
          `, (err) => {
            if (err) {
              console.error('   ❌ Failed to create new payments table:', err);
              db.run('ROLLBACK');
              reject(err);
              return;
            }

            // Copy data from old table
            db.run(`
              INSERT INTO payments_new
              SELECT * FROM payments
            `, (err) => {
              if (err) {
                console.error('   ❌ Failed to copy data:', err);
                db.run('ROLLBACK');
                reject(err);
                return;
              }

              // Drop old table
              db.run('DROP TABLE payments', (err) => {
                if (err) {
                  console.error('   ❌ Failed to drop old table:', err);
                  db.run('ROLLBACK');
                  reject(err);
                  return;
                }

                // Rename new table
                db.run('ALTER TABLE payments_new RENAME TO payments', (err) => {
                  if (err) {
                    console.error('   ❌ Failed to rename table:', err);
                    db.run('ROLLBACK');
                    reject(err);
                    return;
                  }

                  db.run('COMMIT', (err) => {
                    if (err) {
                      console.error('   ❌ Failed to commit:', err);
                      reject(err);
                    } else {
                      console.log('   ✅ Added UNIQUE constraint to stripe_session_id');
                      resolve();
                    }
                  });
                });
              });
            });
          });
        });
      });
    } else {
      console.log('   ⏭️  UNIQUE constraint already exists on stripe_session_id');
    }

    console.log('\n📋 Step 6: Creating AppSumo codes table if missing...');

    await new Promise((resolve) => {
      db.run(`
        CREATE TABLE IF NOT EXISTS appsumo_codes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          code TEXT UNIQUE NOT NULL,
          plan_id TEXT NOT NULL,
          plan_name TEXT NOT NULL,
          monthly_credits INTEGER NOT NULL,
          is_redeemed INTEGER DEFAULT 0,
          redeemed_by_user_id INTEGER,
          redeemed_at DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (redeemed_by_user_id) REFERENCES users(id)
        )
      `, (err) => {
        if (err) {
          console.log('   ⚠️  AppSumo codes table may already exist');
        } else {
          console.log('   ✅ Created appsumo_codes table');
        }
        resolve();
      });
    });

    console.log('\n✅ Migration completed successfully!\n');

    // Verify schema
    console.log('🔍 Verifying final schema...\n');

    db.all('PRAGMA table_info(users)', (err, rows) => {
      if (!err) {
        console.log(`📊 Users table now has ${rows.length} columns`);
      }
    });

    db.all('PRAGMA table_info(payments)', (err, rows) => {
      if (!err) {
        console.log(`📊 Payments table now has ${rows.length} columns`);
      }
    });

    db.all('PRAGMA table_info(reports)', (err, rows) => {
      if (!err) {
        console.log(`📊 Reports table now has ${rows.length} columns`);
      }

      // Close database
      db.close((err) => {
        if (err) {
          console.error('❌ Error closing database:', err);
        } else {
          console.log('\n✅ Database connection closed');
          console.log('🎉 Migration complete! Your database is ready for production.\n');
        }
      });
    });

  } catch (error) {
    console.error('\n❌ Migration failed:', error);
    db.close();
    process.exit(1);
  }
}

// Run migration
migrate();
