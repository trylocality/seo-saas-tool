/**
 * Generate AppSumo Codes - Single Tier (50 Credits/Month)
 * Follows AppSumo requirements:
 * - Single column CSV
 * - No header
 * - Codes 3-200 characters
 * - Randomized, no duplicates
 * - 1,000 codes minimum
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

console.log('🎫 Generating AppSumo Codes (Single Tier - 50 Credits/Month)...\n');

// Generate a unique, randomized code
function generateCode() {
  // Format: APPSUMO-XXXXXXXXXX (10 random characters)
  // Uses crypto for true randomness
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Exclude confusing: 0, O, 1, I
  let code = 'APPSUMO-';

  // Generate 10 random characters
  for (let i = 0; i < 10; i++) {
    const randomIndex = crypto.randomInt(0, chars.length);
    code += chars[randomIndex];
  }

  return code;
}

// Generate codes with uniqueness check
function generateUniqueCodes(count) {
  const codes = new Set();

  console.log(`🔄 Generating ${count} unique codes...\n`);

  while (codes.size < count) {
    const code = generateCode();
    codes.add(code);

    if (codes.size % 100 === 0) {
      console.log(`   ✅ Generated ${codes.size} codes...`);
    }
  }

  // Convert to array and shuffle for additional randomization
  const codesArray = Array.from(codes);

  // Fisher-Yates shuffle
  for (let i = codesArray.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [codesArray[i], codesArray[j]] = [codesArray[j], codesArray[i]];
  }

  return codesArray;
}

// Main execution
const COUNT = 1000; // Generate 1,000 codes
const PLAN_ID = 'lifetime';
const PLAN_NAME = 'Lifetime';
const MONTHLY_CREDITS = 50;

console.log('📋 Configuration:');
console.log(`   Codes to generate: ${COUNT}`);
console.log(`   Plan: ${PLAN_NAME}`);
console.log(`   Credits per month: ${MONTHLY_CREDITS}`);
console.log(`   Code format: APPSUMO-XXXXXXXXXX\n`);

// Generate codes
const codes = generateUniqueCodes(COUNT);

console.log(`\n✅ Generated ${codes.length} unique codes\n`);

// Create CSV for AppSumo (single column, no header)
console.log('📝 Creating AppSumo CSV (single column, no header)...');

const appSumoCSV = codes.join('\n');
fs.writeFileSync(
  path.join(__dirname, 'appsumo-codes.csv'),
  appSumoCSV
);

console.log('✅ Created: appsumo-codes.csv (for AppSumo upload)\n');

// Create internal CSV with metadata (for your database)
console.log('📝 Creating internal CSV (with metadata)...');

const internalCSV = 'code,plan_id,plan_name,monthly_credits\n' +
  codes.map(code => `${code},${PLAN_ID},${PLAN_NAME},${MONTHLY_CREDITS}`).join('\n');

fs.writeFileSync(
  path.join(__dirname, 'appsumo-codes-internal.csv'),
  internalCSV
);

console.log('✅ Created: appsumo-codes-internal.csv (for database import)\n');

// Create plain text list
console.log('📝 Creating plain text list...');

fs.writeFileSync(
  path.join(__dirname, 'appsumo-codes.txt'),
  codes.join('\n')
);

console.log('✅ Created: appsumo-codes.txt\n');

// Sample codes
console.log('📋 Sample codes (first 5):');
console.log('='.repeat(50));
codes.slice(0, 5).forEach((code, i) => {
  console.log(`   ${i + 1}. ${code}`);
});
console.log('='.repeat(50));

console.log('\n✅ Code generation complete!\n');

console.log('📤 Next Steps:');
console.log('   1. Upload "appsumo-codes.csv" to AppSumo Partner Portal');
console.log('   2. Run: node load-appsumo-codes-single-tier.js');
console.log('   3. Test redemption with a sample code\n');

console.log('📊 Files Created:');
console.log('   ✓ appsumo-codes.csv (for AppSumo - SINGLE COLUMN, NO HEADER)');
console.log('   ✓ appsumo-codes-internal.csv (for your database)');
console.log('   ✓ appsumo-codes.txt (plain text backup)\n');
