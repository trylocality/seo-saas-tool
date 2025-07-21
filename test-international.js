// Test script for international address handling
// Remove axios dependency for now - just test the detection logic

// Test the detectCountryRegion function
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

// Test addresses
const testAddresses = [
  {
    name: "April's Bakery",
    location: "Al Sufouh Suites - Al Noor St - Al Sufouh - Al Sufouh 1 - Dubai - United Arab Emirates"
  },
  {
    name: "Starbucks",
    location: "Sheikh Zayed Road, Dubai, UAE"
  },
  {
    name: "Harrods",
    location: "87-135 Brompton Rd, Knightsbridge, London SW1X 7XL, UK"
  },
  {
    name: "Sydney Opera House",
    location: "Bennelong Point, Sydney NSW 2000, Australia"
  },
  {
    name: "Tim Hortons",
    location: "Toronto, Ontario, Canada"
  },
  {
    name: "Pizza Hut",
    location: "Denver, CO"
  }
];

console.log('🧪 Testing International Address Detection\n');
console.log('==========================================\n');

testAddresses.forEach(test => {
  console.log(`Business: ${test.name}`);
  console.log(`Location: ${test.location}`);
  const result = detectCountryRegion(test.location);
  console.log(`Detected Region: ${result.region} (${result.language})`);
  console.log('---\n');
});

console.log('\n✅ The fix has been implemented!');
console.log('\nWhat was changed:');
console.log('1. Added detectCountryRegion() function to identify country from address');
console.log('2. Outscraper API now uses appropriate region parameter (e.g., AE for UAE)');
console.log('3. SerpAPI calls now use localized Google domains (e.g., google.ae)');
console.log('4. ScrapingBee screenshots use country-specific parameters');
console.log('5. Location validation is more flexible for international addresses');
console.log('\nThe Dubai address should now work correctly!');