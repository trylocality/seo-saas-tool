// Test script for database adapter
const DatabaseAdapter = require('./database-adapter');

async function testDatabase() {
  const db = new DatabaseAdapter();
  
  try {
    console.log('🔧 Testing database adapter...\n');
    
    // Initialize connection
    await db.initialize();
    console.log(`✅ Connected to ${db.dbType === 'postgresql' ? 'PostgreSQL' : 'SQLite'}`);
    
    // Setup tables
    console.log('\n📋 Setting up tables...');
    await db.setupTables();
    console.log('✅ Tables created/verified');
    
    // Test user operations
    console.log('\n👤 Testing user operations...');
    
    // Check if test user exists
    const existingUser = await db.get(
      'SELECT * FROM users WHERE email = $1',
      ['test@example.com']
    );
    
    if (!existingUser) {
      console.log('Creating test user...');
      const result = await db.run(
        'INSERT INTO users (email, password_hash, first_name, last_name) VALUES ($1, $2, $3, $4) RETURNING id',
        ['test@example.com', 'hashed_password', 'Test', 'User']
      );
      console.log('✅ User created with ID:', result.lastID);
    } else {
      console.log('✅ Test user already exists with ID:', existingUser.id);
    }
    
    // Get all users
    const users = await db.all('SELECT id, email, first_name, last_name FROM users');
    console.log(`\n📊 Total users in database: ${users.length}`);
    users.forEach(user => {
      console.log(`   - ${user.first_name} ${user.last_name} (${user.email})`);
    });
    
    console.log('\n✅ All tests passed!');
    console.log('\n💡 To switch between databases:');
    console.log('   - For PostgreSQL: Set DATABASE_URL environment variable');
    console.log('   - For SQLite: Leave DATABASE_URL unset');
    
    process.exit(0);
  } catch (error) {
    console.error('\n❌ Test failed:', error);
    process.exit(1);
  }
}

testDatabase();