#!/usr/bin/env node

// Script to convert server-v2.js to support both SQLite and PostgreSQL
const fs = require('fs').promises;

async function convertServerFile() {
  console.log('Converting server-v2.js to support PostgreSQL...');
  
  try {
    // Read the original file
    let content = await fs.readFile('server-v2.js', 'utf8');
    
    // 1. Replace sqlite3 import with database adapter
    content = content.replace(
      "const sqlite3 = require('sqlite3').verbose();",
      "const DatabaseAdapter = require('./database-adapter');"
    );
    
    // 2. Replace database initialization
    content = content.replace(
      /const db = new sqlite3\.Database[\s\S]*?}\);/,
      `const db = new DatabaseAdapter();

// Initialize database connection
(async () => {
  try {
    await db.initialize();
    await db.setupTables();
  } catch (err) {
    console.error('❌ Database initialization failed:', err);
    process.exit(1);
  }
})()`
    );
    
    // 3. Remove the db.serialize block for table creation
    content = content.replace(
      /\/\/ Create tables\s*\n\s*db\.serialize\(\(\) => \{[\s\S]*?\}\);/,
      '// Tables are created in database-adapter.js'
    );
    
    // 4. Convert all db.get calls to async/await with $1 style parameters
    content = content.replace(
      /db\.get\('([^']+)\?([^']*)'[^,]*,\s*\[([^\]]+)\],\s*\(err,\s*(\w+)\)\s*=>\s*\{/g,
      'try {\n    const $4 = await db.get(\'$1$1$2\', [$3]);\n'
    );
    
    // 5. Convert db.run calls for single operations
    content = content.replace(
      /db\.run\('([^']+)\?([^']*)'[^,]*,\s*\[([^\]]+)\],\s*function\(err\)\s*\{/g,
      'try {\n    const result = await db.run(\'$1$1$2\', [$3]);\n'
    );
    
    // 6. Convert db.all calls
    content = content.replace(
      /db\.all\('([^']+)\?([^']*)'[^,]*,\s*\[([^\]]+)\],\s*\(err,\s*(\w+)\)\s*=>\s*\{/g,
      'try {\n    const $4 = await db.all(\'$1$1$2\', [$3]);\n'
    );
    
    // 7. Fix parameter placeholders (? to $1, $2, etc.)
    // This is a more complex operation that needs manual review
    console.log('⚠️  Note: You will need to manually update SQL parameter placeholders from ? to $1, $2, etc.');
    
    // 8. Add async to all route handlers that use database
    content = content.replace(
      /app\.(get|post|put|delete)\('([^']+)',\s*(verifyToken,\s*)?\(req,\s*res\)\s*=>\s*\{/g,
      'app.$1(\'$2\', $3async (req, res) => {'
    );
    
    // Write the converted file
    await fs.writeFile('server-postgres.js', content);
    
    console.log('✅ Conversion complete! Created server-postgres.js');
    console.log('\n⚠️  Important manual steps required:');
    console.log('1. Update all SQL parameter placeholders from ? to $1, $2, etc.');
    console.log('2. Add proper error handling for async/await');
    console.log('3. Test thoroughly before deploying');
    console.log('\nExample SQL parameter conversion:');
    console.log('  Before: SELECT * FROM users WHERE email = ? AND id = ?');
    console.log('  After:  SELECT * FROM users WHERE email = $1 AND id = $2');
    
  } catch (error) {
    console.error('❌ Conversion failed:', error);
  }
}

convertServerFile();