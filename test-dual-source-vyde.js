// Test dual-source validation with Vyde Tax & Accounting
require('dotenv').config();
const axios = require('axios');

const OUTSCRAPER_API_KEY = process.env.OUTSCRAPER_API_KEY;
const GMAPSEXTRACTOR_KEY = process.env.GMAPSEXTRACTOR_KEY;

async function testDualSource() {
  console.log('🔍 Testing Dual-Source Validation\n');
  console.log('Business: Vyde Tax & Accounting');
  console.log('Location: Provo, UT\n');
  console.log('='.repeat(80));

  // 1. Get Outscraper data
  console.log('\n📍 STEP 1: Fetching Outscraper Data...\n');
  let outscraperData = null;
  try {
    const response = await axios.get('https://api.outscraper.com/maps/search-v2', {
      params: {
        query: 'Vyde Tax & Accounting Provo, UT',
        language: 'en',
        region: 'us',
        limit: 3,
        extractContacts: true
      },
      headers: {
        'X-API-KEY': OUTSCRAPER_API_KEY
      },
      timeout: 30000
    });

    if (response.data && response.data.data && response.data.data.length > 0) {
      const businessData = response.data.data[0];
      const businesses = Array.isArray(businessData) ? businessData : [businessData];
      const business = businesses[0];

      outscraperData = {
        name: business.name,
        description: business.description || business.about || '',
        phone: business.phone || '',
        website: business.site || business.website || '',
        verified: business.verified || business.claimed || false,
        social: {},
        photos_count: parseInt(business.photos_count) || 0,
        posts: Array.isArray(business.posts) ? business.posts.length : 0
      };

      console.log('✅ Outscraper Data Retrieved:');
      console.log(`   Name: ${outscraperData.name}`);
      console.log(`   Description: ${outscraperData.description ? `"${outscraperData.description.substring(0, 100)}..." (${outscraperData.description.length} chars)` : '❌ NONE'}`);
      console.log(`   Phone: ${outscraperData.phone}`);
      console.log(`   Website: ${outscraperData.website}`);
      console.log(`   Verified: ${outscraperData.verified}`);
      console.log(`   Photos: ${outscraperData.photos_count}`);
      console.log(`   Posts: ${outscraperData.posts}`);
      console.log(`   Social Links: ${Object.keys(outscraperData.social).length}`);
    }
  } catch (error) {
    console.error('❌ Outscraper Error:', error.message);
  }

  // 2. Get G Maps Extractor data
  console.log('\n🗺️  STEP 2: Fetching G Maps Extractor Data...\n');
  let gmapsData = null;
  try {
    const response = await axios.post('https://cloud.gmapsextractor.com/api/v2/search', {
      q: "Vyde Tax & Accounting Provo, UT",
      page: 1,
      ll: "@40.2338,-111.6585,11z",
      hl: "en",
      gl: "us",
      extra: true
    }, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GMAPSEXTRACTOR_KEY}`
      },
      timeout: 15000
    });

    if (response.data && response.data.data && response.data.data.length > 0) {
      const business = response.data.data[0];

      const social = {};
      if (business.instagram_links && business.instagram_links.length > 0) social.instagram = business.instagram_links[0];
      if (business.facebook_links && business.facebook_links.length > 0) social.facebook = business.facebook_links[0];
      if (business.linkedin_links && business.linkedin_links.length > 0) social.linkedin = business.linkedin_links[0];
      if (business.twitter_links && business.twitter_links.length > 0) social.twitter = business.twitter_links[0];
      if (business.youtube_links && business.youtube_links.length > 0) social.youtube = business.youtube_links[0];

      gmapsData = {
        name: business.name,
        description: business.meta?.description || '',
        phone: business.phone || '',
        website: business.website || business.domain || '',
        verified: business.claimed === 'YES',
        social: social,
        tracking: {
          ga4: business.tracking_ids?.google?.ga4 || '',
          gtm: business.tracking_ids?.google?.gtm || '',
          facebook_pixel: business.tracking_ids?.meta?.pixelId || '',
          linkedin_partner: business.tracking_ids?.linkedin?.partnerId || ''
        }
      };

      console.log('✅ G Maps Extractor Data Retrieved:');
      console.log(`   Name: ${gmapsData.name}`);
      console.log(`   Description: ${gmapsData.description ? `"${gmapsData.description.substring(0, 100)}..." (${gmapsData.description.length} chars)` : '❌ NONE'}`);
      console.log(`   Phone: ${gmapsData.phone}`);
      console.log(`   Website: ${gmapsData.website}`);
      console.log(`   Verified: ${gmapsData.verified}`);
      console.log(`   Social Links: ${Object.keys(gmapsData.social).length}`);
      Object.entries(gmapsData.social).forEach(([platform, url]) => {
        console.log(`      - ${platform}: ${url}`);
      });
      console.log(`   Tracking IDs:`);
      console.log(`      - GA4: ${gmapsData.tracking.ga4 || 'none'}`);
      console.log(`      - GTM: ${gmapsData.tracking.gtm || 'none'}`);
      console.log(`      - FB Pixel: ${gmapsData.tracking.facebook_pixel || 'none'}`);
    }
  } catch (error) {
    console.error('❌ G Maps Extractor Error:', error.message);
  }

  // 3. Dual-Source Validation
  console.log('\n\n🔍 === DUAL-SOURCE VALIDATION RESULTS ===\n');

  if (!outscraperData || !gmapsData) {
    console.log('❌ Cannot perform validation - missing data from one or both sources');
    return;
  }

  // Description validation
  console.log('📝 DESCRIPTION:');
  if (!outscraperData.description && gmapsData.description) {
    console.log('   ✅ MERGE: Using G Maps Extractor description (Outscraper empty)');
    console.log(`   Final: "${gmapsData.description.substring(0, 100)}..."`);
  } else if (outscraperData.description && gmapsData.description) {
    console.log('   ℹ️  BOTH: Both sources have descriptions');
    console.log(`   Outscraper: "${outscraperData.description.substring(0, 80)}..."`);
    console.log(`   G Maps: "${gmapsData.description.substring(0, 80)}..."`);
    console.log('   Decision: Keep Outscraper (GBP description preferred)');
  } else if (outscraperData.description && !gmapsData.description) {
    console.log('   ✅ KEEP: Using Outscraper description');
  } else {
    console.log('   ❌ NONE: Neither source has description');
  }

  // Social links validation
  console.log('\n🔗 SOCIAL LINKS:');
  const outscraperSocials = Object.keys(outscraperData.social).length;
  const gmapsSocials = Object.keys(gmapsData.social).length;

  if (gmapsSocials > outscraperSocials) {
    console.log(`   ✅ MERGE: Using G Maps Extractor (${gmapsSocials} links vs ${outscraperSocials})`);
    const merged = { ...outscraperData.social, ...gmapsData.social };
    Object.entries(merged).forEach(([platform, url]) => {
      console.log(`      - ${platform}: ${url}`);
    });
  } else if (outscraperSocials > gmapsSocials) {
    console.log(`   ✅ KEEP: Using Outscraper (${outscraperSocials} links vs ${gmapsSocials})`);
  } else if (gmapsSocials === 0 && outscraperSocials === 0) {
    console.log('   ⚠️  NONE: Neither source has social links');
  } else {
    console.log(`   ℹ️  EQUAL: Both have ${gmapsSocials} links`);
  }

  // Verification validation
  console.log('\n✓ VERIFICATION:');
  if (outscraperData.verified === gmapsData.verified) {
    console.log(`   ✅ MATCH: Both agree (${outscraperData.verified})`);
  } else {
    console.log(`   ⚠️  MISMATCH: Outscraper=${outscraperData.verified}, G Maps=${gmapsData.verified}`);
    console.log(`   Decision: Use ${outscraperData.verified || gmapsData.verified} (trust positive verification)`);
  }

  // Basic data comparison
  console.log('\n📊 BASIC DATA COMPARISON:');
  console.log(`   Phone: ${outscraperData.phone === gmapsData.phone ? '✅ Match' : `⚠️  Differ (OS: "${outscraperData.phone}" vs GM: "${gmapsData.phone}")`}`);
  console.log(`   Website: ${outscraperData.website === gmapsData.website ? '✅ Match' : `⚠️  Differ (OS: "${outscraperData.website}" vs GM: "${gmapsData.website}")`}`);

  // Unique features
  console.log('\n🎯 UNIQUE FEATURES:');
  console.log(`   📸 Photos (Outscraper only): ${outscraperData.photos_count}`);
  console.log(`   📄 Posts (Outscraper only): ${outscraperData.posts}`);
  console.log(`   🔍 Tracking IDs (G Maps only):`);
  console.log(`      - GA4: ${gmapsData.tracking.ga4 || 'none'}`);
  console.log(`      - GTM: ${gmapsData.tracking.gtm || 'none'}`);

  console.log('\n' + '='.repeat(80));
  console.log('\n✅ Dual-source validation complete!\n');
}

testDualSource().catch(console.error);
