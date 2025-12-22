/**
 * Load AppSumo Codes (Single Tier - 50 Credits/Month) into SQLite Database
 * Reads from appsumo-codes-internal.csv and inserts into database
 */

const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'seo_audit_v3.db');
const CSV_PATH = path.join(__dirname, 'appsumo-codes-internal.csv');

console.log('📦 Loading AppSumo Codes (Single Tier) into Database...\n');

// Check if CSV exists
if (!fs.existsSync(CSV_PATH)) {
  console.error('❌ appsumo-codes-internal.csv not found!');
  console.log('ℹ️  Run generate-appsumo-codes-single-tier.js first');
  process.exit(1);
}

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('❌ Failed to connect to database:', err);
    process.exit(1);
  }
  console.log('✅ Connected to SQLite database\n');
});

async function loadCodes() {
  try {
    // Check if codes already exist
    const existingCount = await new Promise((resolve, reject) => {
      db.get('SELECT COUNT(*) as count FROM appsumo_codes', (err, row) => {
        if (err) reject(err);
        else resolve(row.count);
      });
    });

    if (existingCount > 0) {
      console.log(`⚠️  Database already has ${existingCount} codes`);
      console.log('🗑️  Clearing old codes to load new single-tier codes...\n');

      await new Promise((resolve, reject) => {
        db.run('DELETE FROM appsumo_codes', (err) => {
          if (err) reject(err);
          else {
            console.log('✅ Old codes cleared\n');
            resolve();
          }
        });
      });
    }

    // Read CSV file
    const csvContent = fs.readFileSync(CSV_PATH, 'utf8');
    const lines = csvContent.trim().split('\n');

    // Skip header row
    const codeRows = lines.slice(1);

    console.log(`📋 Found ${codeRows.length} codes in CSV file`);
    console.log('📦 Plan: Lifetime (50 credits/month)\n');

    let insertedCount = 0;
    let errorCount = 0;

    console.log('🔄 Inserting codes into database...\n');

    // Process codes in transaction
    db.serialize(() => {
      db.run('BEGIN TRANSACTION');

      const stmt = db.prepare(`
        INSERT INTO appsumo_codes (code, plan_id, plan_name, monthly_credits, is_redeemed)
        VALUES (?, ?, ?, ?, ?)
      `);

      for (const line of codeRows) {
        const [code, planId, planName, monthlyCredits] = line.split(',');

        if (!code || !planId || !planName || !monthlyCredits) {
          console.log(`⚠️  Skipping invalid line: ${line}`);
          errorCount++;
          continue;
        }

        stmt.run(
          code.trim(),
          planId.trim(),
          planName.trim(),
          parseInt(monthlyCredits.trim()),
          0, // is_redeemed = false
          (err) => {
            if (err) {
              console.error(`❌ Failed to insert code ${code}:`, err.message);
              errorCount++;
            }
          }
        );

        insertedCount++;

        if (insertedCount % 100 === 0) {
          console.log(`   ✅ Inserted ${insertedCount} codes...`);
        }
      }

      stmt.finalize((err) => {
        if (err) {
          console.error('❌ Error finalizing statement:', err);
          db.run('ROLLBACK');
          db.close();
          process.exit(1);
        }

        db.run('COMMIT', (err) => {
          if (err) {
            console.error('❌ Error committing transaction:', err);
            db.close();
            process.exit(1);
          }

          console.log(`\n✅ Successfully loaded ${insertedCount} AppSumo codes!`);

          if (errorCount > 0) {
            console.log(`⚠️  ${errorCount} errors occurred during import`);
          }

          console.log('\n📊 Summary:');
          console.log('='.repeat(50));
          console.log(`   Plan: Lifetime`);
          console.log(`   Credits per month: 50`);
          console.log(`   Total codes: ${insertedCount}`);
          console.log('='.repeat(50));

          // Verify insertion
          db.get('SELECT COUNT(*) as total FROM appsumo_codes', (err, row) => {
            if (!err) {
              console.log(`\n✅ Database now contains ${row.total} total codes\n`);
            }

            // Sample some codes
            db.all('SELECT code, plan_name, monthly_credits FROM appsumo_codes LIMIT 5', (err, rows) => {
              if (!err) {
                console.log('📋 Sample codes in database:');
                console.log('='.repeat(50));
                rows.forEach((row, i) => {
                  console.log(`   ${i + 1}. ${row.code} (${row.plan_name}, ${row.monthly_credits} credits/month)`);
                });
                console.log('='.repeat(50));
              }

              console.log('\n📝 Next Steps:');
              console.log('   1. ✅ Codes loaded in database');
              console.log('   2. 📤 Upload appsumo-codes.csv to AppSumo');
              console.log('   3. 🧪 Test redemption with sample code');
              console.log('   4. 🚀 Go live!\n');

              db.close(() => {
                console.log('✅ Database connection closed\n');
                process.exit(0);
              });
            });
          });
        });
      });
    });

  } catch (error) {
    console.error('❌ Fatal error:', error);
    db.close();
    process.exit(1);
  }
}

// Run the loader
loadCodes();
