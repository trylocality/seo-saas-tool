// Test G Maps Extractor with correct endpoint and auth
require('dotenv').config();
const axios = require('axios');

const API_KEY = '5IXM3HNhhjPPYnOR68YuGk6eiRAqED2XUqzXk4pLonPelHdr';

async function testGMapsExtractor() {
  console.log('🗺️  Testing G Maps Extractor API...\n');
  console.log('📍 Searching: Vyde Tax & Accounting, Provo, UT\n');

  try {
    const response = await axios.post('https://cloud.gmapsextractor.com/api/v2/search', {
      q: "Vyde Tax & Accounting Provo, UT",
      page: 1,
      ll: "@40.2338,-111.6585,11z",  // Provo, UT coordinates
      hl: "en",
      gl: "us",
      extra: true  // Include emails and social media
    }, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_KEY}`
      },
      timeout: 30000
    });

    console.log('✅ SUCCESS! API Response received\n');
    console.log('📊 Response Status:', response.status);
    console.log('📊 Data:', JSON.stringify(response.data, null, 2));

    if (response.data) {
      analyzeData(response.data);
    }

  } catch (error) {
    console.error('❌ Error:', error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
    }
  }
}

function analyzeData(data) {
  console.log('\n\n🎯 ANALYZING DATA AGAINST OUR 15 RANKING FACTORS:\n');
  console.log('='.repeat(80));

  // Extract business data
  const results = data.results || data.data || data;
  const business = Array.isArray(results) ? results[0] : results;

  if (!business) {
    console.log('❌ No business data found in response');
    return;
  }

  const factors = {
    '1. Description': checkField(business, ['description', 'about', 'businessDescription', 'desc']),
    '2. Categories': checkField(business, ['categories', 'types', 'category', 'businessType', 'type']),
    '3. Photos': checkField(business, ['photos', 'photoCount', 'photos_count', 'images', 'photo']),
    '4. Reviews': checkField(business, ['reviews', 'reviewCount', 'review_count', 'totalReviews', 'reviews_count']),
    '5. Rating': checkField(business, ['rating', 'averageRating', 'stars']),
    '6. Product Tiles': checkField(business, ['products', 'services', 'offerings', 'menu']),
    '7. Posts': checkField(business, ['posts', 'updates', 'googlePosts']),
    '8. Social Profiles': checkField(business, ['social', 'socialLinks', 'socialMedia', 'socials']),
    '9. Hours': checkField(business, ['hours', 'openingHours', 'workingHours', 'businessHours', 'working_hours']),
    '10. Address': checkField(business, ['address', 'fullAddress', 'location', 'full_address']),
    '11. Phone': checkField(business, ['phone', 'phoneNumber', 'contact', 'phone_number']),
    '12. Website': checkField(business, ['website', 'url', 'site']),
    '13. Verified': checkField(business, ['verified', 'claimed', 'isVerified']),
    '14. Place ID': checkField(business, ['placeId', 'place_id', 'googleId', 'id', 'google_id']),
    '15. Business Name': checkField(business, ['name', 'title', 'businessName'])
  };

  for (const [factor, result] of Object.entries(factors)) {
    const status = result.found ? '✅' : '❌';
    const value = result.found ? `${result.field} = ${JSON.stringify(result.value).substring(0, 100)}` : 'NOT FOUND';
    console.log(`${status} ${factor.padEnd(25)} ${value}`);
  }

  console.log('\n' + '='.repeat(80));
  console.log('\n📋 ALL AVAILABLE FIELDS:\n');
  console.log(Object.keys(business).sort().join(', '));

  console.log('\n\n🔍 FULL BUSINESS OBJECT:\n');
  console.log(JSON.stringify(business, null, 2));
}

function checkField(obj, possibleKeys) {
  for (const key of possibleKeys) {
    if (obj && obj[key] !== undefined && obj[key] !== null) {
      return {
        found: true,
        field: key,
        value: obj[key]
      };
    }
  }
  return { found: false };
}

testGMapsExtractor();
