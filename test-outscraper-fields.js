// Test to see all available fields from Outscraper API
const axios = require('axios');
require('dotenv').config();

const OUTSCRAPER_API_KEY = process.env.OUTSCRAPER_API_KEY;

async function testOutscraperFields() {
  try {
    console.log('🔍 Testing Outscraper API fields...\n');

    // Using Elevate Fitness since we know it has product tiles
    const query = 'Elevate Fitness & Rehab Lehi, UT';

    const response = await axios.get('https://api.outscraper.com/maps/search-v2', {
      params: {
        query: query,
        language: 'en',
        region: 'us',
        limit: 1
        // NOT specifying fields - get ALL available fields
      },
      headers: {
        'X-API-KEY': OUTSCRAPER_API_KEY
      },
      timeout: 15000
    });

    console.log('Response status:', response.status);

    // Handle async response
    if (response.status === 202) {
      const requestId = response.data.id;
      console.log('Async request ID:', requestId);

      // Poll for results
      for (let i = 0; i < 10; i++) {
        await new Promise(resolve => setTimeout(resolve, 3000));

        const pollResponse = await axios.get(`https://api.outscraper.com/requests/${requestId}`, {
          headers: {
            'X-API-KEY': OUTSCRAPER_API_KEY
          }
        });

        if (pollResponse.data.status === 'Success') {
          const business = pollResponse.data.data[0][0];

          console.log('\n📊 ALL AVAILABLE FIELDS:');
          console.log(Object.keys(business).sort().join('\n'));

          console.log('\n\n🔍 PRODUCT/SERVICE RELATED FIELDS:');
          const productFields = Object.keys(business).filter(k =>
            k.toLowerCase().includes('product') ||
            k.toLowerCase().includes('service') ||
            k.toLowerCase().includes('menu') ||
            k.toLowerCase().includes('item')
          );

          if (productFields.length > 0) {
            productFields.forEach(field => {
              console.log(`\n${field}:`, JSON.stringify(business[field], null, 2).substring(0, 300));
            });
          } else {
            console.log('❌ No product/service fields found in Outscraper response');
          }

          console.log('\n\n📝 ABOUT FIELD STRUCTURE:');
          console.log('about:', JSON.stringify(business.about, null, 2));

          console.log('\n\n📝 DESCRIPTION FIELD:');
          console.log('description:', business.description);
          console.log('Type:', typeof business.description);

          console.log('\n\n📄 OTHER TEXT FIELDS:');
          const textFields = ['business_description', 'business_info', 'details', 'info', 'overview'];
          textFields.forEach(field => {
            if (business[field] !== undefined) {
              console.log(`${field}:`, business[field]);
            }
          });

          return;
        }
      }

      console.log('Timeout waiting for results');
    }

  } catch (error) {
    console.error('Error:', error.message);
    if (error.response) {
      console.error('Response:', error.response.data);
    }
  }
}

testOutscraperFields();
