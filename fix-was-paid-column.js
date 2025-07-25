require('dotenv').config();
const DatabaseAdapter = require('./database-adapter');

async function fixWasPaidColumn() {
  const db = new DatabaseAdapter();
  
  try {
    console.log('🔧 Connecting to database...');
    await db.initialize();
    
    console.log('🔍 Checking if was_paid column exists...');
    
    if (process.env.DATABASE_TYPE === 'postgres') {
      // Check if column exists in PostgreSQL
      const columnCheck = await db.query(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = 'reports' AND column_name = 'was_paid'
      `);
      
      if (columnCheck.length === 0) {
        console.log('⚠️  was_paid column missing, adding it now...');
        await db.query(`ALTER TABLE reports ADD COLUMN was_paid BOOLEAN DEFAULT FALSE`);
        console.log('✅ Successfully added was_paid column to reports table');
      } else {
        console.log('✅ was_paid column already exists');
      }
    } else {
      // SQLite check
      const tableInfo = await db.query(`PRAGMA table_info(reports)`);
      const hasWasPaid = tableInfo.some(col => col.name === 'was_paid');
      
      if (!hasWasPaid) {
        console.log('⚠️  was_paid column missing, adding it now...');
        await db.query(`ALTER TABLE reports ADD COLUMN was_paid INTEGER DEFAULT 0`);
        console.log('✅ Successfully added was_paid column to reports table');
      } else {
        console.log('✅ was_paid column already exists');
      }
    }
    
    // Verify the column was added
    console.log('🔍 Verifying column addition...');
    const testQuery = await db.query('SELECT was_paid FROM reports LIMIT 1');
    console.log('✅ Column verified successfully');
    
  } catch (error) {
    console.error('❌ Error fixing was_paid column:', error);
    process.exit(1);
  } finally {
    await db.close();
    console.log('🔒 Database connection closed');
  }
}

// Run the fix
fixWasPaidColumn().then(() => {
  console.log('✅ Migration completed successfully');
  process.exit(0);
}).catch(err => {
  console.error('❌ Migration failed:', err);
  process.exit(1);
});