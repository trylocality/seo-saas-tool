require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const axios = require('axios');
const fs = require('fs').promises;
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// ==========================================
// CONFIGURATION & ENVIRONMENT VARIABLES
// ==========================================

const app = express();
const PORT = process.env.PORT || 3000;

// API Keys - Set these in your environment
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-this-123456789';
const OUTSCRAPER_API_KEY = process.env.OUTSCRAPER_API_KEY;
const SCRAPINGBEE_API_KEY = process.env.SCRAPINGBEE_API_KEY;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const SERPAPI_KEY = process.env.SERPAPI_KEY;

// Stripe Configuration
const STRIPE_PRICES = {
  oneTime: process.env.STRIPE_PRICE_ONE_TIME || 'price_1ReQIIDEq7s1BPEYZfi9Nk6C',
  starter: process.env.STRIPE_PRICE_STARTER || 'price_1ReQPvDEq7s1BPEYDbR6A3IJ',
  pro: process.env.STRIPE_PRICE_PRO || 'price_1ReR1MDEq7s1BPEYHzSW0uTn'
};

const CREDIT_AMOUNTS = {
  oneTime: 1,
  starter: 10,
  pro: 50
};

// White Label Configuration
const BRAND_CONFIG = {
  name: process.env.BRAND_NAME || 'Locality',
  logo: process.env.BRAND_LOGO || '/assets/logo.png',
  primaryColor: process.env.BRAND_PRIMARY_COLOR || '#007bff',
  supportEmail: process.env.BRAND_SUPPORT_EMAIL || 'support@locality.com'
};
// ==========================================
// DATABASE SETUP
// ==========================================

const db = new sqlite3.Database('./seo_audit_v3.db', (err) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
    process.exit(1);
  }
  console.log('✅ Connected to SQLite database (v3)');
});

// Create tables
db.serialize(() => {
  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      credits_remaining INTEGER DEFAULT 1,
      subscription_tier TEXT DEFAULT 'free',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Reports table
  db.run(`
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      business_name TEXT NOT NULL,
      city TEXT NOT NULL,
      industry TEXT NOT NULL,
      website TEXT,
      report_data TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);

  // Screenshot cache table
  db.run(`
    CREATE TABLE IF NOT EXISTS screenshot_cache (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      business_name TEXT NOT NULL,
      city TEXT NOT NULL,
      screenshot_filename TEXT NOT NULL,
      screenshot_url TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      file_size INTEGER,
      UNIQUE(business_name, city)
    )
  `);

  // Payments table
  db.run(`
    CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      amount INTEGER NOT NULL,
      credits_purchased INTEGER NOT NULL,
      stripe_payment_id TEXT,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);
});

// ==========================================
// MIDDLEWARE
// ==========================================

app.use(cors());
app.use('/api/stripe-webhook', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.static('public'));

// Auth middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    db.get('SELECT * FROM users WHERE id = ?', [decoded.userId], (err, user) => {
      if (err) {
        console.error('Database error in auth:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      req.user = user;
      next();
    });
  });
};
// ==========================================
// UTILITY FUNCTIONS
// ==========================================

// Ensure screenshots directory exists
const screenshotsDir = path.join(__dirname, 'public', 'screenshots');
async function ensureScreenshotsDir() {
  try {
    await fs.mkdir(screenshotsDir, { recursive: true });
  } catch (error) {
    console.log('Screenshots directory already exists or created');
  }
}

// Clean expired cache entries
function cleanupExpiredCache() {
  db.run('DELETE FROM screenshot_cache WHERE expires_at < datetime("now")', function(err) {
    if (err) {
      console.error('Cache cleanup error:', err);
    } else if (this.changes > 0) {
      console.log(`🧹 Cleaned up ${this.changes} expired cached screenshots`);
    }
  });
}

// Run cleanup every 24 hours
setInterval(cleanupExpiredCache, 24 * 60 * 60 * 1000);

// ==========================================
// DATA COLLECTION FUNCTIONS
// ==========================================

// 1. OUTSCRAPER - Get primary business data
async function getOutscraperData(businessName, location) {
  try {
    const query = `${businessName} ${location}`;
    console.log(`🔍 Outscraper search: ${query}`);
    
    if (!OUTSCRAPER_API_KEY) {
      throw new Error('Outscraper API key not configured');
    }
    
    const response = await axios.get('https://api.outscraper.com/maps/search-v2', {
      params: {
        query: query,
        language: 'en',
        region: 'US',
        limit: 1
      },
      headers: {
        'X-API-KEY': OUTSCRAPER_API_KEY
      },
      timeout: 15000
    });
    
    console.log('🔍 Outscraper response status:', response.status);
    
    // Handle async response
    if (response.status === 202 && response.data.status === 'Pending') {
      console.log('⏳ Outscraper job is async, polling for results...');
      
      const resultsUrl = response.data.results_location;
      
      // Poll for results (max 30 seconds)
      for (let i = 0; i < 6; i++) {
        await new Promise(resolve => setTimeout(resolve, 5000));
        
        try {
          const resultResponse = await axios.get(resultsUrl, {
            headers: {
              'X-API-KEY': OUTSCRAPER_API_KEY
            },
            timeout: 10000
          });
          
          console.log('🔍 POLL RESPONSE STRUCTURE:', typeof resultResponse.data.data, Array.isArray(resultResponse.data.data));
          if (resultResponse.data && resultResponse.data.data && resultResponse.data.data.length > 0) {
            const businessData = resultResponse.data.data[0];
            console.log('🔍 BUSINESS DATA TYPE:', typeof businessData, 'IS_ARRAY:', Array.isArray(businessData));
            
            // Handle if business data is an array (extract first element) or direct object
            const business = Array.isArray(businessData) ? businessData[0] : businessData;
            console.log(`✅ Outscraper found: ${business.name || business.title || businessName}`);
            console.log('🔍 FINAL BUSINESS OBJECT:', JSON.stringify(business, null, 2));
            
            return {
              name: business.name || business.title || businessName,
              phone: business.phone || '',
              website: business.site || business.website || '',
              rating: parseFloat(business.rating) || 0,
              reviews: parseInt(business.reviews) || parseInt(business.reviews_count) || 0,
              verified: business.verified || business.claimed || false,
              description: business.description || '',
              photos_count: parseInt(business.photos_count) || parseInt(business.photos) || 0,
              categories: business.subtypes ? business.subtypes.split(', ') : (business.type ? [business.type] : []),
              hours: business.working_hours || business.hours || null,
              place_id: business.place_id || business.google_id,
              google_id: business.google_id || business.place_id,
              reviews_link: business.reviews_link
            };
          }
        } catch (pollError) {
          console.log(`⏳ Poll ${i + 1}: Still processing...`);
        }
      }
      
      throw new Error('Outscraper polling timeout - no results after 30 seconds');
    }
    
    // Handle immediate response
    if (response.data && response.data.data && response.data.data.length > 0) {
      const businessData = response.data.data[0];
      console.log('🔍 IMMEDIATE BUSINESS DATA TYPE:', typeof businessData, 'IS_ARRAY:', Array.isArray(businessData));
      
      // Handle if business data is an array (extract first element) or direct object
      const business = Array.isArray(businessData) ? businessData[0] : businessData;
      console.log(`✅ Outscraper found: ${business.name || business.title || businessName}`);
      
      return {
        name: business.name || business.title || businessName,
        phone: business.phone || '',
        website: business.site || business.website || '',
        rating: parseFloat(business.rating) || 0,
        reviews: parseInt(business.reviews) || parseInt(business.reviews_count) || 0,
        verified: business.verified || business.claimed || false,
        description: business.description || '',
        photos_count: parseInt(business.photos_count) || parseInt(business.photos) || 0,
        categories: business.subtypes ? business.subtypes.split(', ') : (business.type ? [business.type] : []),
        hours: business.working_hours || business.hours || null,
        place_id: business.place_id || business.google_id,
        google_id: business.google_id || business.place_id,
        reviews_link: business.reviews_link
      };
    }
    
    throw new Error('No business found in Outscraper response');
    
  } catch (error) {
    console.error('❌ Outscraper error:', error.message);
    throw new Error(`Outscraper failed: ${error.message}`);
  }
}
// 2. SCRAPINGBEE SCREENSHOT - For visual analysis
async function takeBusinessProfileScreenshot(businessName, location) {
  try {
    console.log(`📸 Taking ScrapingBee screenshot: ${businessName}`);
    
    await ensureScreenshotsDir();
    
    if (!SCRAPINGBEE_API_KEY) {
      throw new Error('ScrapingBee API key not configured');
    }
    
    const searchQuery = `${businessName} ${location}`;
    const googleSearchUrl = `https://www.google.com/search?q=${encodeURIComponent(searchQuery)}`;
    
    const params = {
      api_key: SCRAPINGBEE_API_KEY,
      url: googleSearchUrl,
      custom_google: 'true',
      stealth_proxy: 'true',
      render_js: 'true',
      screenshot: 'true',
      screenshot_full_page: 'true',
      wait: 4000,
      window_width: 1920,
      window_height: 1080,
      block_resources: 'false'
    };
    
    const response = await axios.get('https://app.scrapingbee.com/api/v1/', {
      params: params,
      timeout: 120000,
      responseType: 'arraybuffer'
    });
    
    if (response.status === 200 && response.headers['content-type'].includes('image')) {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const safeBusinessName = businessName.replace(/[^a-zA-Z0-9]/g, '_');
      const filename = `${safeBusinessName}_${timestamp}.png`;
      const filepath = path.join(screenshotsDir, filename);
      
      await fs.writeFile(filepath, response.data);
      
      console.log(`✅ Screenshot saved: ${filename}`);
      
      return {
        success: true,
        filename: filename,
        filepath: filepath,
        url: `/screenshots/${filename}`,
        fileSize: response.data.length
      };
    } else {
      throw new Error(`Unexpected response: ${response.status}`);
    }
    
  } catch (error) {
    console.error('❌ Screenshot error:', error.message);
    throw new Error(`Screenshot failed: ${error.message}`);
  }
}

// 3. AI ANALYSIS - Extract posts, services, Q&As from screenshot
async function analyzeScreenshotWithAI(screenshotPath, businessName) {
  try {
    console.log(`🤖 AI analyzing screenshot: ${businessName}`);
    
    if (!OPENAI_API_KEY) {
      throw new Error('OpenAI API key not configured');
    }
    
    const imageBuffer = await fs.readFile(screenshotPath);
    const base64Image = imageBuffer.toString('base64');
    
    const analysisPrompt = `
    Analyze this Google Business Profile screenshot for "${businessName}".
    
    Look for these specific elements:
    1. POSTS/UPDATES: Recent posts, updates, or announcements in the "Posts" or "Updates" section
    2. PRODUCT TILES: Product/service tiles or listings in a dedicated products section
    3. Q&A SECTION: Questions and answers from customers
    4. SOCIAL MEDIA: Social media profile links or icons
    
    Respond ONLY with valid JSON:
    {
      "posts": {
        "hasRecent": false,
        "count": 0
      },
      "productTiles": {
        "hasAny": false,
        "count": 0
      },
      "qa": {
        "hasAny": false,
        "count": 0
      },
      "social": {
        "hasAny": false,
        "count": 0
      }
    }
    `;
    
    const openaiResponse = await axios.post('https://api.openai.com/v1/chat/completions', {
      model: 'gpt-4o',
      messages: [{
        role: 'user',
        content: [{
          type: 'text',
          text: analysisPrompt
        }, {
          type: 'image_url',
          image_url: {
            url: `data:image/png;base64,${base64Image}`,
            detail: 'high'
          }
        }]
      }],
      max_tokens: 500
    }, {
      headers: {
        'Authorization': `Bearer ${OPENAI_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    
    const aiResponse = openaiResponse.data.choices[0].message.content;
    let cleanedResponse = aiResponse.trim();
    
    // Clean markdown formatting
    if (cleanedResponse.startsWith('```json')) {
      cleanedResponse = cleanedResponse.replace(/^```json\s*/, '');
    }
    if (cleanedResponse.endsWith('```')) {
      cleanedResponse = cleanedResponse.replace(/\s*```$/, '');
    }
    
    const analysis = JSON.parse(cleanedResponse);
    
    console.log(`✅ AI Analysis: Posts: ${analysis.posts.hasRecent}, Product Tiles: ${analysis.productTiles.hasAny}, Q&A: ${analysis.qa.hasAny}, Social: ${analysis.social.hasAny}`);
    
    return analysis;
    
  } catch (error) {
    console.error('❌ AI analysis error:', error.message);
    throw new Error(`AI analysis failed: ${error.message}`);
  }
}
// 4. CITATION CHECKER - Check presence in major directories
async function checkCitations(businessName, location) {
  try {
    console.log(`🔍 Checking citations: ${businessName} in ${location}`);
    
    if (!SERPAPI_KEY) {
      throw new Error('SerpAPI key not configured');
    }
    
    const directories = [
      { name: 'Yelp', domain: 'yelp.com' },
      { name: 'Better Business Bureau', domain: 'bbb.org' },
      { name: 'Yellow Pages', domain: 'yellowpages.com' },
      { name: 'Apple Maps', domain: 'maps.apple.com' },
      { name: 'Facebook Business', domain: 'facebook.com' },
      { name: 'Foursquare', domain: 'foursquare.com' },
      { name: 'Bing Maps', domain: 'bing.com/maps' }
    ];
    
    const found = [];
    const checked = [];
    
    for (const directory of directories) {
      try {
        const searchQuery = `site:${directory.domain} "${businessName}" ${location}`;
        
        const response = await axios.get('https://serpapi.com/search.json', {
          params: {
            engine: 'google',
            q: searchQuery,
            api_key: SERPAPI_KEY,
            num: 3
          },
          timeout: 10000
        });
        
        const hasResults = response.data.organic_results && response.data.organic_results.length > 0;
        
        checked.push({
          directory: directory.name,
          domain: directory.domain,
          found: hasResults,
          searchQuery: searchQuery
        });
        
        if (hasResults) {
          found.push({
            directory: directory.name,
            domain: directory.domain,
            url: response.data.organic_results[0].link
          });
        }
        
        // Small delay to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 500));
        
      } catch (dirError) {
        console.error(`❌ Citation check failed for ${directory.name}:`, dirError.message);
        checked.push({
          directory: directory.name,
          domain: directory.domain,
          found: false,
          error: dirError.message
        });
      }
    }
    
    console.log(`📊 Citations found: ${found.length}/${directories.length}`);
    
    return {
      found: found,
      checked: checked,
      total: directories.length,
      stats: {
        found: found.length,
        missing: directories.length - found.length,
        percentage: Math.round((found.length / directories.length) * 100),
        score: found.length * 2 // 2 points per citation found
      }
    };
    
  } catch (error) {
    console.error('❌ Citation check error:', error.message);
    throw new Error(`Citation check failed: ${error.message}`);
  }
}

// 5. WEBSITE ANALYSIS - Check for GBP embed and get content for smart suggestions
async function analyzeWebsite(websiteUrl, location) {
  try {
    console.log(`🌐 Analyzing website: ${websiteUrl}`);
    
    if (!websiteUrl) {
      return {
        hasGBPEmbed: false,
        hasLocalizedPage: false,
        services: [],
        content: '',
        note: 'No website provided'
      };
    }
    
    // Ensure URL has protocol
    if (!websiteUrl.startsWith('http')) {
      websiteUrl = 'https://' + websiteUrl;
    }
    
    const response = await axios.get(websiteUrl, {
      timeout: 15000,
      maxRedirects: 3,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });
    
    const htmlContent = response.data;
    const htmlLower = htmlContent.toLowerCase();
    
    // Check for GBP embed
    const gbpIndicators = [
      'maps.google.com/maps',
      'google.com/maps/embed',
      'maps/embed',
      'place_id=',
      'maps.googleapis.com'
    ];
    const hasGBPEmbed = gbpIndicators.some(indicator => htmlLower.includes(indicator));
    
    // Check for localized landing page - search for both city AND state
    const { city, state } = extractCityState(location);
    const cityLower = city.toLowerCase();
    const stateLower = state.toLowerCase();
    const localizedIndicators = [
      // City-specific patterns
      `/${cityLower}`,
      `${cityLower}-`,
      `/location/${cityLower}`,
      `/service-area/${cityLower}`,
      `/serving-${cityLower}`,
      `>${cityLower} location<`,
      `>${cityLower} office<`,
      // State-specific patterns
      `/${stateLower}`,
      `${stateLower}-`,
      `/location/${stateLower}`,
      `/service-area/${stateLower}`,
      `/serving-${stateLower}`,
      `>${stateLower} location<`,
      `>${stateLower} office<`,
      // Common state name patterns
      `utah`, `texas`, `california`, `florida`, `nevada`, `colorado`, `arizona` // add more as needed
    ];
    const hasLocalizedPage = localizedIndicators.some(indicator => htmlLower.includes(indicator));
    
    // Extract services for smart suggestions
    const services = extractServicesFromHTML(htmlContent);
    
    console.log(`${hasGBPEmbed ? '✅' : '❌'} GBP Embed | ${hasLocalizedPage ? '✅' : '❌'} Localized Page | ${services.length} services found`);
    
    return {
      hasGBPEmbed: hasGBPEmbed,
      hasLocalizedPage: hasLocalizedPage,
      services: services,
      content: htmlContent.substring(0, 5000), // First 5000 chars for analysis
      note: 'Website analysis completed'
    };
    
  } catch (error) {
    console.error('❌ Website analysis error:', error.message);
    return {
      hasGBPEmbed: false,
      hasLocalizedPage: false,
      services: [],
      content: '',
      note: `Website analysis failed: ${error.message}`
    };
  }
}

// Helper function to extract city and state from location string
function extractCityState(location) {
  // Handle full address format (e.g., "123 Main St, Miami, FL 33101")
  const parts = location.split(',').map(p => p.trim());
  
  if (parts.length === 2) {
    // Simple "City, ST" format
    return {
      city: parts[0],
      state: parts[1]
    };
  } else if (parts.length >= 3) {
    // Full address format - extract city and state from the last parts
    const lastPart = parts[parts.length - 1].trim();
    const secondLastPart = parts[parts.length - 2].trim();
    
    // Check if last part is a zip code
    if (/^\d{5}(-\d{4})?$/.test(lastPart)) {
      // Extract state from second last part (e.g., "FL 33101" -> "FL")
      const stateMatch = secondLastPart.match(/^([A-Z]{2})\s+\d{5}/i) || secondLastPart.match(/^([A-Z]{2})$/i);
      if (stateMatch) {
        return {
          city: parts[parts.length - 3] || secondLastPart.replace(/\s*[A-Z]{2}\s*\d{5}.*$/i, '').trim(),
          state: stateMatch[1].toUpperCase()
        };
      }
    } else if (/^[A-Z]{2}$/i.test(lastPart)) {
      // Last part is state abbreviation
      return {
        city: secondLastPart,
        state: lastPart.toUpperCase()
      };
    }
  }
  
  // Fallback - try to split by comma and use first two parts
  return {
    city: parts[0] || location,
    state: parts[1] || ''
  };
}

// Helper function to extract services from HTML
function extractServicesFromHTML(htmlContent) {
  try {
    const services = [];
    const htmlLower = htmlContent.toLowerCase();
    
    // Look for service-related sections
    const servicePatterns = [
      /services?[^<]*:([^<]+)/gi,
      /we offer[^<]*:([^<]+)/gi,
      /our services include[^<]*:([^<]+)/gi,
      /<h[1-6][^>]*>([^<]*(?:service|solution|product)[^<]*)<\/h[1-6]>/gi,
      /<li[^>]*>([^<]*(?:service|solution|consulting|management|design|development)[^<]*)<\/li>/gi
    ];
    
    servicePatterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(htmlContent)) !== null && services.length < 10) {
        const service = match[1].trim().replace(/[^\w\s-]/g, '');
        if (service.length > 5 && service.length < 100) {
          services.push(service);
        }
      }
    });
    
    // Remove duplicates and return top 6
    return [...new Set(services)].slice(0, 6);
    
  } catch (error) {
    console.error('❌ Service extraction error:', error.message);
    return [];
  }
}
// 6. REVIEWS ANALYSIS - Check for recent reviews and business responses
async function analyzeReviews(businessName, location, placeId) {
  try {
    console.log(`📝 Analyzing reviews for: ${businessName}`);
    
    if (!SERPAPI_KEY) {
      throw new Error('SerpAPI key not configured');
    }
    
    // First get place info if we don't have a reliable place_id
    let businessPlaceId = placeId;
    
    if (!businessPlaceId) {
      console.log('🔍 Getting place info from SerpAPI...');
      
      const searchResponse = await axios.get('https://serpapi.com/search.json', {
        params: {
          engine: 'google_local',
          q: `${businessName} ${location}`,
          api_key: SERPAPI_KEY
        },
        timeout: 15000
      });
      
      if (searchResponse.data.local_results && searchResponse.data.local_results.length > 0) {
        const business = searchResponse.data.local_results[0];
        businessPlaceId = business.place_id;
        console.log(`✅ Found place_id: ${businessPlaceId}`);
      }
    }
    
    if (!businessPlaceId) {
      return { 
        hasRecentReview: false,
        hasBusinessResponses: false,
        note: 'Could not find place_id for detailed review analysis'
      };
    }
    
    // Get detailed reviews using place_id
    console.log('🔍 Getting detailed reviews...');
    
    const reviewsResponse = await axios.get('https://serpapi.com/search.json', {
      params: {
        engine: 'google_maps_reviews',
        place_id: businessPlaceId,
        api_key: SERPAPI_KEY
      },
      timeout: 15000
    });
    
    if (reviewsResponse.data.error) {
      return { 
        hasRecentReview: false,
        hasBusinessResponses: false,
        note: `Reviews not available: ${reviewsResponse.data.error}`
      };
    }
    
    if (reviewsResponse.data.reviews && reviewsResponse.data.reviews.length > 0) {
      const reviews = reviewsResponse.data.reviews;
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      
      // Check for recent reviews
      const hasRecentReview = reviews.some(review => {
        if (!review.iso_date) return false;
        const reviewDate = new Date(review.iso_date);
        return reviewDate > thirtyDaysAgo;
      });
      
      // Check for business responses
      const hasBusinessResponses = reviews.some(review => 
        review.response && review.response.snippet && review.response.snippet.trim().length > 0
      );
      
      console.log(`✅ Reviews analysis: ${reviews.length} total, recent: ${hasRecentReview}, responses: ${hasBusinessResponses}`);
      
      return { 
        hasRecentReview: hasRecentReview,
        hasBusinessResponses: hasBusinessResponses,
        reviewCount: reviews.length,
        note: 'Review analysis completed'
      };
    }
    
    return { 
      hasRecentReview: false,
      hasBusinessResponses: false,
      reviewCount: 0,
      note: 'No detailed reviews available'
    };
    
  } catch (error) {
    console.error('❌ Reviews analysis error:', error.message);
    return { 
      hasRecentReview: false,
      hasBusinessResponses: false,
      reviewCount: 0,
      note: `Reviews analysis failed: ${error.message}`
    };
  }
}

// 7. COMPLETE SCORING SYSTEM (UPDATED V3)
function calculateScore(data) {
  console.log(`📊 Calculating score for: ${data.businessInfo.businessName}`);
  console.log('🔍 SCORING DEBUG - Raw Data:');
  console.log(`   Photos: ${data.outscraper.photos_count}`);
  console.log(`   Categories: ${data.outscraper.categories.length} (${data.outscraper.categories.join(', ')})`);
  console.log(`   Reviews: ${data.outscraper.reviews}, Rating: ${data.outscraper.rating}`);
  console.log(`   Verified: ${data.outscraper.verified}`);
  console.log(`   Description length: ${data.outscraper.description?.length || 0}`);
  
  const scores = {
    claimed: 0,           // 8 pts
    description: 0,       // 10 pts
    categories: 0,        // 8 pts
    productTiles: 0,      // 10 pts
    photos: 0,            // 8 pts
    posts: 0,             // 8 pts
    qa: 0,                // 4 pts
    social: 0,            // 2 pts
    reviews: 0,           // 12 pts (3 each for 4 criteria)
    citations: 0,         // 14 pts
    gbpEmbed: 0,          // 8 pts
    landingPage: 0        // 8 pts
  };
  
  const details = {};
  
  // 1. CLAIMED PROFILE (8 pts) - Binary
  if (data.outscraper.verified || data.outscraper.rating > 0) {
    scores.claimed = 8;
    details.claimed = { status: 'GOOD', message: 'Google Business Profile is claimed and verified' };
  } else {
    scores.claimed = 0;
    details.claimed = { status: 'MISSING', message: 'Claim your Google Business Profile' };
  }
  
  // 2. BUSINESS DESCRIPTION (10 pts) - 0/5/10 based on criteria
  const desc = data.outscraper.description;
  const descAnalysis = analyzeDescriptionCriteria(desc, data.businessInfo.businessName, data.businessInfo.location, data.businessInfo.industry);
  
  if (!desc) {
    scores.description = 0;
    details.description = { status: 'MISSING', message: 'Add a business description' };
  } else if (descAnalysis.criteriaCount === 3) {
    scores.description = 10;
    details.description = { status: 'GOOD', message: 'Description has all 3 criteria: localized keywords, services overview, and call-to-action' };
  } else {
    scores.description = 5;
    details.description = { status: 'NEEDS IMPROVEMENT', message: `Description missing ${3 - descAnalysis.criteriaCount} criteria` };
  }
  
  // 3. CATEGORIES (8 pts) - 0 if only primary, 5 if 2-3 total, 8 if 4+ total
  const totalCategories = data.outscraper.categories.length;
  if (totalCategories >= 4) {
    scores.categories = 8;
    details.categories = { status: 'GOOD', message: `${totalCategories} categories found` };
  } else if (totalCategories >= 2) {
    scores.categories = 5;
    details.categories = { status: 'NEEDS IMPROVEMENT', message: `${totalCategories} categories found, add more` };
  } else {
    scores.categories = 0;
    details.categories = { status: 'MISSING', message: 'Add secondary business categories' };
  }
  
  // 4. PRODUCT TILES (10 pts) - Binary
  if (data.aiAnalysis.productTiles && data.aiAnalysis.productTiles.hasAny) {
    scores.productTiles = 10;
    details.productTiles = { status: 'GOOD', message: `${data.aiAnalysis.productTiles.count} product tiles found` };
  } else {
    scores.productTiles = 0;
    details.productTiles = { status: 'MISSING', message: 'Add product/service tiles' };
  }
  
  // 5. PHOTOS (8 pts) - 0 if none, 4 if <10, 8 if 10+
  const photoCount = data.outscraper.photos_count;
  if (photoCount >= 10) {
    scores.photos = 8;
    details.photos = { status: 'GOOD', message: `${photoCount} photos found` };
  } else if (photoCount > 0) {
    scores.photos = 4;
    details.photos = { status: 'NEEDS IMPROVEMENT', message: `${photoCount} photos found, add more` };
  } else {
    scores.photos = 0;
    details.photos = { status: 'MISSING', message: 'Upload business photos' };
  }
  
  // 6. POSTS (8 pts) - Binary: recent activity
  if (data.aiAnalysis.posts && data.aiAnalysis.posts.hasRecent) {
    scores.posts = 8;
    details.posts = { status: 'GOOD', message: 'Recent posts found' };
  } else {
    scores.posts = 0;
    details.posts = { status: 'MISSING', message: 'Start posting regular updates' };
  }
  
  // 7. Q&A (4 pts) - Give half credit if we can't detect properly
  if (data.aiAnalysis.qa && data.aiAnalysis.qa.hasAny) {
    scores.qa = 4;
    details.qa = { status: 'GOOD', message: `${data.aiAnalysis.qa.count} Q&As found` };
  } else {
    // Give half credit since detection isn't always reliable
    scores.qa = 2;
    details.qa = { status: 'UNCERTAIN', message: 'Q&A section not clearly detected - may exist but not visible in screenshot' };
  }
  
  // 8. SOCIAL PROFILES (2 pts) - Binary
  if (data.aiAnalysis.social && data.aiAnalysis.social.hasAny) {
    scores.social = 2;
    details.social = { status: 'GOOD', message: `${data.aiAnalysis.social.count} social links found` };
  } else {
    scores.social = 0;
    details.social = { status: 'MISSING', message: 'Add social media links' };
  }
  
  // 9. REVIEWS (12 pts) - 3 pts each for 4 criteria - ADD DEBUG LOGGING
  let reviewScore = 0;
  const reviewCriteria = [];
  
  console.log(`🔍 REVIEW DEBUG: Reviews: ${data.outscraper.reviews}, Rating: ${data.outscraper.rating}`);
  console.log(`🔍 REVIEW DEBUG: Recent review: ${data.reviewsAnalysis?.hasRecentReview}, Business responses: ${data.reviewsAnalysis?.hasBusinessResponses}`);
  
  if (data.outscraper.reviews >= 10) {
    reviewScore += 3;
    reviewCriteria.push('10+ reviews');
  }
  if (data.outscraper.rating >= 4.4) {
    reviewScore += 3;
    reviewCriteria.push('4.4+ rating');
  }
  if (data.reviewsAnalysis && data.reviewsAnalysis.hasRecentReview) {
    reviewScore += 3;
    reviewCriteria.push('recent review');
  }
  if (data.reviewsAnalysis && data.reviewsAnalysis.hasBusinessResponses) {
    reviewScore += 3;
    reviewCriteria.push('business responses');
  }
  
  console.log(`🔍 REVIEW DEBUG: Final review score: ${reviewScore}/12, Criteria met: ${reviewCriteria.join(', ')}`);
  
  scores.reviews = reviewScore;
  details.reviews = { 
    status: reviewScore >= 9 ? 'GOOD' : (reviewScore >= 6 ? 'NEEDS IMPROVEMENT' : 'MISSING'),
    message: `${data.outscraper.reviews} reviews, ${data.outscraper.rating} rating. Has: ${reviewCriteria.join(', ') || 'none'}` 
  };
  
  // 10. CITATIONS (14 pts) - 2 pts per directory found
  scores.citations = data.citations.stats.score;
  if (scores.citations >= 10) {
    details.citations = { status: 'GOOD', message: `Found in ${data.citations.stats.found}/7 directories` };
  } else if (scores.citations >= 6) {
    details.citations = { status: 'NEEDS IMPROVEMENT', message: `Found in ${data.citations.stats.found}/7 directories` };
  } else {
    details.citations = { status: 'MISSING', message: `Found in ${data.citations.stats.found}/7 directories - need more` };
  }
  
  // 11. GBP EMBED (8 pts) - Binary
  if (data.websiteAnalysis.hasGBPEmbed) {
    scores.gbpEmbed = 8;
    details.gbpEmbed = { status: 'GOOD', message: 'Google Business Profile embedded on website' };
  } else {
    scores.gbpEmbed = 0;
    details.gbpEmbed = { status: 'MISSING', message: 'Embed Google Business Profile on website' };
  }
  
  // 12. LOCAL LANDING PAGE (8 pts) - Binary
  if (data.websiteAnalysis.hasLocalizedPage) {
    scores.landingPage = 8;
    details.landingPage = { status: 'GOOD', message: 'City-specific landing page found' };
  } else {
    scores.landingPage = 0;
    details.landingPage = { status: 'MISSING', message: 'Create localized landing page' };
  }
  
  const totalScore = Object.values(scores).reduce((sum, score) => sum + score, 0);
  
  console.log(`📊 Final Score: ${totalScore}/100`);
  
  return {
    totalScore: totalScore,
    maxScore: 100,
    scores: scores,
    details: details
  };
}
// Helper function to analyze description criteria
function analyzeDescriptionCriteria(description, businessName, location, industry) {
  if (!description) {
    return { criteriaCount: 0, hasLocalKeywords: false, hasServices: false, hasCTA: false };
  }
  
  const descLower = description.toLowerCase();
  const { city } = extractCityState(location);
  const cityLowerCase = city.toLowerCase();
  
  // Check for localized keywords
  const localPatterns = [
    `${cityLowerCase}`,
    `local`,
    `serving ${cityLowerCase}`,
    `${cityLowerCase} area`,
    `${cityLowerCase} ${industry.toLowerCase()}`,
    `${industry.toLowerCase()} in ${cityLowerCase}`
  ];
  const hasLocalKeywords = localPatterns.some(pattern => descLower.includes(pattern));
  
  // Check for services overview
  const servicePatterns = [
    'we provide', 'we offer', 'our services', 'services include',
    'we specialize', 'expertise in', 'professional'
  ];
  const hasServices = servicePatterns.some(pattern => descLower.includes(pattern));
  
  // Check for call to action
  const ctaPatterns = [
    'contact us', 'call us', 'reach out', 'schedule', 'book',
    'get started', 'learn more', 'visit us', 'today'
  ];
  const hasCTA = ctaPatterns.some(pattern => descLower.includes(pattern));
  
  const criteriaCount = [hasLocalKeywords, hasServices, hasCTA].filter(Boolean).length;
  
  return { criteriaCount, hasLocalKeywords, hasServices, hasCTA };
}

// 8. SMART SUGGESTION GENERATION
async function generateSmartSuggestions(businessInfo, scoreData, websiteServices) {
  try {
    console.log(`🧠 Generating smart suggestions for: ${businessInfo.businessName}`);
    
    if (!OPENAI_API_KEY) {
      throw new Error('OpenAI API key not configured for smart suggestions');
    }
    
    const suggestions = {};
    const { businessName, location, industry, website } = businessInfo;
    const { city, state } = extractCityState(location);
    
    // 1. Business Description (if needed)
    if (scoreData.scores.description < 10) {
      const descriptionPrompt = `
      Generate an SEO-optimized Google Business Profile description for:
      Business: ${businessName}
      Industry: ${industry}
      Location: ${city}, ${state}
      Website Services Found: ${websiteServices.join(', ') || 'None detected'}
      
      Requirements:
      - 400+ characters
      - Include local keywords (${city}, ${industry})
      - Mention specific services
      - Include a call-to-action
      - Professional but approachable tone
      
      Return only the description text, no quotes or formatting.
      `;
      
      suggestions.businessDescription = await callOpenAI(descriptionPrompt, 'description');
    }
    
    // 2. Category Suggestions (if needed)
    if (scoreData.scores.categories < 8) {
      const categoryPrompt = `
      Suggest Google Business Profile categories for:
      Business: ${businessName}
      Industry: ${industry}
      Services: ${websiteServices.join(', ') || 'General services'}
      
      Provide 6-8 relevant categories from Google's official category list.
      Include one primary category and 5-7 secondary categories.
      Return as a simple list, one per line, no numbering.
      Focus on categories that actually exist in Google Business Profile.
      `;
      
      suggestions.categories = await callOpenAI(categoryPrompt, 'categories');
    }
    
    // 3. Product Tiles (if needed)
    if (scoreData.scores.productTiles < 10) {
      const tilesPrompt = `
      Create 4-6 product/service tiles for Google Business Profile:
      Business: ${businessName}
      Industry: ${industry}
      Website Services: ${websiteServices.join(', ') || 'General services'}
      
      For each tile, provide:
      - Service name (keyword-rich, 2-4 words)
      - Description (1-2 sentences, under 100 characters)
      
      Format as:
      Service Name
      Description text here
      
      (blank line between each)
      `;
      
      suggestions.productTiles = await callOpenAI(tilesPrompt, 'product tiles');
    }
    
    // 4. Post Ideas (if needed)
    if (scoreData.scores.posts < 8) {
      const postsPrompt = `
      Create 5 Google Business Post ideas for:
      Business: ${businessName}
      Industry: ${industry}
      Location: ${city}, ${state}
      
      Each post should be:
      - 150-200 characters
      - Include local keywords
      - Have a call-to-action
      - Be engaging and professional
      
      Format as numbered list (1-5).
      `;
      
      suggestions.posts = await callOpenAI(postsPrompt, 'posts');
    }
    
    // 5. Q&A Content (if needed)
    if (scoreData.scores.qa < 4) {
      const qaPrompt = `
      Create 5 Q&A pairs for Google Business Profile:
      Business: ${businessName}
      Industry: ${industry}
      Location: ${city}, ${state}
      
      Questions should be common customer inquiries.
      Answers should be helpful and include local keywords.
      
      Format as:
      Q: Question here?
      A: Answer here.
      
      (blank line between pairs)
      `;
      
      suggestions.qa = await callOpenAI(qaPrompt, 'Q&A');
    }
    
    // 6. Review Management (if needed)
    if (scoreData.scores.reviews < 8) {
      const reviewsPrompt = `
      Create a review management strategy for:
      Business: ${businessName}
      Industry: ${industry}
      Location: ${city}, ${state}
      
      Provide:
      - 3 ways to encourage more reviews
      - 2 review request templates (1 follow-up email, 1 text message)
      - Best practices for responding to reviews
      
      Keep it practical and actionable.
      `;
      
      suggestions.reviews = await callOpenAI(reviewsPrompt, 'reviews');
    }
    
    // 7. Citation Building (if needed)
    if (scoreData.scores.citations < 8) {
      const citationsPrompt = `
      Create a citation building strategy for:
      Business: ${businessName}
      Industry: ${industry}
      Location: ${city}, ${state}
      
      Provide:
      - Top 10 citation sources for ${industry} businesses
      - NAP (Name, Address, Phone) consistency checklist
      - Monthly citation building action plan
      
      Focus on industry-specific and local directories.
      `;
      
      suggestions.citations = await callOpenAI(citationsPrompt, 'citations');
    }
    
    // 8. Landing Page Optimization (if needed)
    if (scoreData.scores.landingPage < 8) {
      const landingPagePrompt = `
      Create a local landing page optimization strategy for:
      Business: ${businessName}
      Industry: ${industry}
      Location: ${city}, ${state}
      Website: ${website}
      
      Provide:
      - 5 key elements for the local landing page
      - Local SEO keywords to include
      - Content structure recommendations
      - Local trust signals to add
      
      Focus on converting local visitors.
      `;
      
      suggestions.landingPage = await callOpenAI(landingPagePrompt, 'landingPage');
    }
    
    console.log(`✅ Smart suggestions generated for ${Object.keys(suggestions).length} areas`);
    
    return suggestions;
    
  } catch (error) {
    console.error('❌ Smart suggestions error:', error.message);
    return {
      error: `Smart suggestions failed: ${error.message}`
    };
  }
}

// Helper function to call OpenAI
async function callOpenAI(prompt, type) {
  try {
    const response = await axios.post('https://api.openai.com/v1/chat/completions', {
      model: 'gpt-4o-mini',
      messages: [{
        role: 'user',
        content: prompt
      }],
      max_tokens: 500,
      temperature: 0.7
    }, {
      headers: {
        'Authorization': `Bearer ${OPENAI_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    
    const result = response.data.choices[0].message.content.trim();
    console.log(`✅ Generated ${type}: ${result.length} characters`);
    
    return {
      title: `${type.charAt(0).toUpperCase() + type.slice(1)} Recommendation`,
      content: result,
      instructions: getInstructionsFor(type)
    };
    
  } catch (error) {
    console.error(`❌ OpenAI error for ${type}:`, error.message);
    return {
      title: `${type.charAt(0).toUpperCase() + type.slice(1)} Recommendation`,
      content: `Failed to generate ${type} suggestion`,
      instructions: getInstructionsFor(type),
      error: error.message
    };
  }
}

// Helper function to get instructions
function getInstructionsFor(type) {
  const instructions = {
    'description': 'Copy this description and paste it into your Google Business Profile "About" section.',
    'categories': 'Add these categories in your Google Business Profile > Info > Category section.',
    'product tiles': 'Add these as Products/Services in your Google Business Profile > Products section.',
    'posts': 'Use these as Google Posts - post 1-2 per week for better engagement.',
    'Q&A': 'Add these questions and answers to your Google Business Profile Q&A section.'
  };
  
  return instructions[type] || 'Follow Google Business Profile guidelines for implementation.';
}
// ==========================================
// MAIN REPORT GENERATION (COMPLETE VERSION)
// ==========================================

async function generateCompleteReport(businessName, location, industry, website) {
  console.log(`🚀 Generating COMPLETE report for: ${businessName} in ${location}`);
  
  const errors = [];
  let partialData = {};
  
  try {
    // Step 1: Get primary business data from Outscraper
    console.log('📍 Step 1: Getting business data...');
    try {
      partialData.outscraper = await getOutscraperData(businessName, location);
    } catch (error) {
      errors.push(`Outscraper: ${error.message}`);
      throw new Error('Failed to get basic business data - cannot continue');
    }
    
    // Step 2: Take screenshot for visual analysis
    console.log('📸 Step 2: Taking screenshot...');
    try {
      const screenshot = await takeBusinessProfileScreenshot(businessName, location);
      partialData.screenshot = screenshot;
      
      // Step 3: AI analysis of screenshot
      console.log('🤖 Step 3: AI analyzing screenshot...');
      partialData.aiAnalysis = await analyzeScreenshotWithAI(screenshot.filepath, businessName);
    } catch (error) {
      errors.push(`Screenshot/AI: ${error.message}`);
      partialData.aiAnalysis = {
        posts: { hasRecent: false, count: 0 },
        productTiles: { hasAny: false, count: 0 },
        qa: { hasAny: false, count: 0 },
        social: { hasAny: false, count: 0 }
      };
    }
    
    // Step 4: Check citations
    console.log('🔍 Step 4: Checking citations...');
    try {
      partialData.citations = await checkCitations(businessName, location);
    } catch (error) {
      errors.push(`Citations: ${error.message}`);
      partialData.citations = {
        found: [],
        checked: [],
        total: 7,
        stats: { found: 0, missing: 7, percentage: 0, score: 0 }
      };
    }
    
    // Step 5: Analyze website
    console.log('🌐 Step 5: Analyzing website...');
    try {
      partialData.websiteAnalysis = await analyzeWebsite(website, location);
    } catch (error) {
      errors.push(`Website: ${error.message}`);
      partialData.websiteAnalysis = {
        hasGBPEmbed: false,
        hasLocalizedPage: false,
        services: [],
        content: '',
        note: 'Website analysis failed'
      };
    }
    
    // Step 6: Analyze reviews
    console.log('📝 Step 6: Analyzing reviews...');
    try {
      partialData.reviewsAnalysis = await analyzeReviews(businessName, location, partialData.outscraper.place_id);
    } catch (error) {
      errors.push(`Reviews: ${error.message}`);
      partialData.reviewsAnalysis = {
        hasRecentReview: false,
        hasBusinessResponses: false,
        reviewCount: 0,
        note: 'Reviews analysis failed'
      };
    }
    
    // Step 7: Compile data for scoring
    const compiledData = {
      businessInfo: { businessName, location, industry, website },
      outscraper: partialData.outscraper,
      aiAnalysis: partialData.aiAnalysis,
      citations: partialData.citations,
      websiteAnalysis: partialData.websiteAnalysis,
      reviewsAnalysis: partialData.reviewsAnalysis,
      screenshot: partialData.screenshot
    };
    
    // Step 8: Calculate score
    console.log('📊 Step 8: Calculating score...');
    const scoreData = calculateScore(compiledData);
    
    // Step 9: Generate smart suggestions
    console.log('🧠 Step 9: Generating smart suggestions...');
    let smartSuggestions = {};
    try {
      smartSuggestions = await generateSmartSuggestions(
        { businessName, location, industry, website },
        scoreData,
        partialData.websiteAnalysis.services || []
      );
    } catch (error) {
      errors.push(`Smart Suggestions: ${error.message}`);
      smartSuggestions = { error: error.message };
    }
    
    // Step 10: Generate action plan
    console.log('📋 Step 10: Creating action plan...');
    const actionPlan = generateActionPlan(scoreData);
    
    // Step 11: Build final report
    const report = {
      success: true,
      business: { name: businessName, location, industry, website },
      generatedDate: new Date().toLocaleDateString(),
      
      // Audit Overview
      auditOverview: {
        title: "Local SEO Audit Results",
        overallScore: {
          score: scoreData.totalScore,
          maxScore: 100,
          grade: getScoreGrade(scoreData.totalScore),
          message: getScoreMessage(scoreData.totalScore)
        },
        factors: Object.entries(scoreData.scores).map(([key, score]) => ({
          id: key,
          name: formatFactorName(key),
          score: score,
          maxScore: getMaxScore(key),
          status: scoreData.details[key]?.status || 'UNKNOWN',
          message: scoreData.details[key]?.message || ''
        }))
      },
      
      // Smart Suggestions
      smartSuggestions: {
        title: "Smart Optimization Recommendations",
        subtitle: "AI-generated content tailored to your business",
        suggestions: smartSuggestions
      },
      
      // Citations Analysis
      citationsAnalysis: {
        title: "Local Citations Report",
        subtitle: "Your presence across major directories",
        data: partialData.citations,
        recommendations: generateCitationRecommendations(partialData.citations)
      },
      
      // Action Plan
      actionPlan: {
        title: "Priority Action Plan",
        subtitle: "Step-by-step roadmap to improve your local SEO",
        actions: actionPlan
      },
      
      // Technical Details
      technicalDetails: {
        apiCalls: {
          outscraper: partialData.outscraper ? 'SUCCESS' : 'FAILED',
          screenshot: partialData.screenshot ? 'SUCCESS' : 'FAILED',
          aiAnalysis: partialData.aiAnalysis ? 'SUCCESS' : 'FAILED',
          citations: partialData.citations ? 'SUCCESS' : 'FAILED',
          website: partialData.websiteAnalysis ? 'SUCCESS' : 'FAILED',
          reviews: partialData.reviewsAnalysis ? 'SUCCESS' : 'FAILED'
        },
        errors: errors,
        costs: {
          outscraper: 0.01,
          scrapingbee: partialData.screenshot ? 0.015 : 0,
          openai_analysis: partialData.aiAnalysis ? 0.02 : 0,
          openai_suggestions: Object.keys(smartSuggestions).length * 0.01,
          serpapi_citations: 0.02,
          serpapi_reviews: 0.02,
          total: 0.085
        }
      }
    };
    
    console.log(`✅ COMPLETE Report generated successfully - Score: ${scoreData.totalScore}/100`);
    if (errors.length > 0) {
      console.log(`⚠️ ${errors.length} non-critical errors occurred`);
    }
    
    return report;
    
  } catch (error) {
    console.error('❌ Critical report generation error:', error);
    throw error;
  }
}

// ==========================================
// HELPER FUNCTIONS
// ==========================================

function getScoreGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

function getScoreMessage(score) {
  if (score >= 90) return 'Excellent local SEO foundation with minor optimization opportunities';
  if (score >= 80) return 'Strong local presence with some key areas for improvement';
  if (score >= 70) return 'Good foundation but needs focused optimization in several areas';
  if (score >= 60) return 'Basic local presence with significant improvement opportunities';
  if (score >= 40) return 'Weak local SEO foundation requiring immediate attention';
  return 'Critical local SEO issues that must be addressed immediately';
}

function formatFactorName(key) {
  const nameMap = {
    claimed: 'Claimed Profile',
    description: 'Business Description',
    categories: 'Categories',
    productTiles: 'Product/Service Tiles',
    photos: 'Photos',
    posts: 'Post Activity',
    qa: 'Q&A Section',
    social: 'Social Media Links',
    reviews: 'Customer Reviews',
    citations: 'Local Citations',
    gbpEmbed: 'GBP Website Embed',
    landingPage: 'Localized Landing Page'
  };
  return nameMap[key] || key;
}

function getMaxScore(key) {
  const maxScores = {
    claimed: 8, description: 10, categories: 8, productTiles: 10,
    photos: 8, posts: 8, qa: 4, social: 2,
    reviews: 12, citations: 14, gbpEmbed: 8, landingPage: 8
  };
  return maxScores[key] || 0;
}

function generateActionPlan(scoreData) {
  const actions = [];
  
  const actionMap = {
    claimed: { task: 'Claim Google Business Profile', time: '10 minutes', priority: 'CRITICAL' },
    description: { task: 'Optimize Business Description', time: '15 minutes', priority: 'HIGH' },
    categories: { task: 'Add Secondary Categories', time: '10 minutes', priority: 'HIGH' },
    productTiles: { task: 'Add Product/Service Tiles', time: '30 minutes', priority: 'HIGH' },
    photos: { task: 'Upload High-Quality Photos', time: '1 hour', priority: 'MEDIUM' },
    posts: { task: 'Start Weekly Google Posts', time: '15 min/week', priority: 'MEDIUM' },
    qa: { task: 'Populate Q&A Section', time: '30 minutes', priority: 'LOW' },
    social: { task: 'Add Social Media Links', time: '10 minutes', priority: 'LOW' },
    reviews: { task: 'Implement Review Strategy', time: '2-4 weeks', priority: 'HIGH' },
    citations: { task: 'Build Local Citations', time: '2-4 hours', priority: 'HIGH' },
    gbpEmbed: { task: 'Embed GBP on Website', time: '15 minutes', priority: 'MEDIUM' },
    landingPage: { task: 'Create Localized Landing Page', time: '2-4 hours', priority: 'MEDIUM' }
  };
  
  Object.entries(scoreData.scores).forEach(([key, score]) => {
    const detail = scoreData.details[key];
    const action = actionMap[key];
    
    if (action && detail) {
      let priority = action.priority;
      if (detail.status === 'GOOD') priority = 'COMPLETE';
      
      actions.push({
        id: key,
        task: action.task,
        completed: detail.status === 'GOOD',
        priority: priority,
        estimatedTime: action.time,
        currentScore: score,
        maxScore: getMaxScore(key),
        message: detail.message
      });
    }
  });
  
  // Sort by priority
  const priorityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'COMPLETE': 0 };
  actions.sort((a, b) => priorityOrder[b.priority] - priorityOrder[a.priority]);
  
  return actions;
}

function generateCitationRecommendations(citationsData) {
  const missing = citationsData.checked.filter(check => !check.found);
  
  return {
    summary: `Found in ${citationsData.stats.found} out of 7 major directories`,
    score: citationsData.stats.score,
    maxScore: 14,
    missingDirectories: missing.map(dir => dir.directory),
    recommendations: missing.length > 0 ? 
      `Focus on getting listed in: ${missing.slice(0, 3).map(dir => dir.directory).join(', ')}` :
      'Excellent citation coverage across all major directories'
  };
}
// ==========================================
// API ROUTES
// ==========================================

// Basic routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Local SEO Audit v3 is working!', 
    timestamp: new Date(),
    version: '3.0',
    brand: BRAND_CONFIG,
    apis: {
      outscraper: !!OUTSCRAPER_API_KEY,
      scrapingbee: !!SCRAPINGBEE_API_KEY,
      openai: !!OPENAI_API_KEY,
      serpapi: !!SERPAPI_KEY
    }
  });
});

// Authentication routes
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    
    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }
    
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, existingUser) => {
      if (err) {
        console.error('Database error in signup:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (existingUser) {
        return res.status(400).json({ error: 'User already exists with this email' });
      }
      
      const passwordHash = await bcrypt.hash(password, 10);
      
      db.run(
        'INSERT INTO users (email, password_hash, first_name, last_name) VALUES (?, ?, ?, ?)',
        [email, passwordHash, firstName, lastName],
        function(err) {
          if (err) {
            console.error('Error creating user:', err);
            return res.status(500).json({ error: 'Failed to create user' });
          }
          
          const userId = this.lastID;
          const token = jwt.sign({ userId: userId }, JWT_SECRET, { expiresIn: '7d' });
          
          console.log(`✅ New user created: ${email}`);
          
          res.json({
            success: true,
            token,
            user: {
              id: userId,
              email: email,
              firstName: firstName,
              lastName: lastName,
              creditsRemaining: 1,
              subscriptionTier: 'free'
            }
          });
        }
      );
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('Database error in login:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!user) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }
      
      const validPassword = await bcrypt.compare(password, user.password_hash);
      if (!validPassword) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }
      
      const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
      
      console.log(`✅ User logged in: ${email}`);
      
      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name,
          creditsRemaining: user.credits_remaining,
          subscriptionTier: user.subscription_tier
        }
      });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/profile', authenticateToken, (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
      firstName: req.user.first_name,
      lastName: req.user.last_name,
      creditsRemaining: req.user.credits_remaining,
      subscriptionTier: req.user.subscription_tier
    }
  });
});

// COMPLETE REPORT GENERATION FOR PRODUCTION
app.post('/api/generate-report', authenticateToken, async (req, res) => {
  try {
    console.log(`📊 Report request from user ${req.user.email}`);
    console.log('🔍 DEBUG: Request body:', req.body);
    
    if (req.user.credits_remaining <= 0) {
      return res.status(402).json({ error: 'No credits remaining. Please purchase more credits.' });
    }
    
    // Handle both old and new frontend formats
    const { businessName, location, city, industry, category, website } = req.body;
    const finalLocation = location || city;
    const finalIndustry = industry || category;
    
    if (!businessName || !finalLocation || !finalIndustry) {
      return res.status(400).json({ error: 'Business name, location, and industry are required' });
    }
    
    // Validate location format (should be "City, ST")
    if (!finalLocation.includes(',')) {
      return res.status(400).json({ error: 'Location must be in format "City, ST" (e.g., "Denver, CO")' });
    }
    
    console.log(`🏢 Generating COMPLETE report for: ${businessName} in ${finalLocation} (${finalIndustry})`);
    
    // Generate complete report with all features
    const report = await generateCompleteReport(businessName, finalLocation, finalIndustry, website);
    
    // Save report
    db.run(
      'INSERT INTO reports (user_id, business_name, city, industry, website, report_data) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, businessName, finalLocation, finalIndustry, website || null, JSON.stringify(report)],
      function(err) {
        if (err) {
          console.error('Error saving report:', err);
        } else {
          console.log(`💾 Report saved with ID: ${this.lastID}`);
        }
      }
    );
    
    // Deduct credit
    db.run(
      'UPDATE users SET credits_remaining = credits_remaining - 1 WHERE id = ?',
      [req.user.id],
      function(err) {
        if (err) {
          console.error('Error updating credits:', err);
        } else {
          console.log(`💳 Credit deducted. User has ${req.user.credits_remaining - 1} credits remaining`);
        }
      }
    );

    console.log(`✅ COMPLETE Report generated successfully for ${businessName}`);
    res.json(report);
    
  } catch (error) {
    console.error('❌ Report generation error:', error);
    res.status(500).json({ 
      error: 'Failed to generate report. Please try again.',
      details: error.message
    });
  }
});

// Get user's reports history
app.get('/api/user-reports', authenticateToken, async (req, res) => {
  try {
    console.log(`📋 Loading reports for user ${req.user.id}`);
    
    db.all(
      'SELECT id, business_name, city, industry, website, created_at FROM reports WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.id],
      (err, reports) => {
        if (err) {
          console.error('Error loading reports:', err);
          return res.status(500).json({ error: 'Failed to load reports' });
        }
        
        console.log(`✅ Found ${reports.length} reports for user ${req.user.id}`);
        
        res.json({
          success: true,
          reports: reports
        });
      }
    );
  } catch (error) {
    console.error('Error in user-reports endpoint:', error);
    res.status(500).json({ error: 'Failed to load reports' });
  }
});

// API status endpoint
app.get('/api/status', (req, res) => {
  res.json({
    server: 'Local SEO Audit v3',
    status: 'running',
    timestamp: new Date().toISOString(),
    apis: {
      outscraper: !!OUTSCRAPER_API_KEY ? 'configured' : 'missing',
      scrapingbee: !!SCRAPINGBEE_API_KEY ? 'configured' : 'missing',
      openai: !!OPENAI_API_KEY ? 'configured' : 'missing',
      serpapi: !!SERPAPI_KEY ? 'configured' : 'missing'
    },
    database: 'connected',
    version: '3.0.0'
  });
});

// ==========================================
// FEEDBACK API ENDPOINT
// ==========================================

app.post('/api/feedback', authenticateToken, async (req, res) => {
  try {
    const { rating, type, message, email, reportData } = req.body;
    const userId = req.user.id;
    
    // Validate required fields
    if (!rating || !type || !message) {
      return res.status(400).json({ error: 'Rating, type, and message are required' });
    }
    
    // Validate rating range
    if (rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Rating must be between 1 and 5' });
    }
    
    // Validate feedback type
    const validTypes = ['general', 'bug', 'feature', 'performance'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ error: 'Invalid feedback type' });
    }
    
    console.log(`💬 Feedback received: ${rating} stars, Type: ${type}, User: ${userId}`);
    
    // Create feedback table if it doesn't exist
    db.run(`CREATE TABLE IF NOT EXISTS feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      rating INTEGER NOT NULL,
      type TEXT NOT NULL,
      message TEXT NOT NULL,
      email TEXT,
      report_data TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
    
    // Insert feedback into database
    const stmt = db.prepare(`
      INSERT INTO feedback (user_id, rating, type, message, email, report_data)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    stmt.run(
      userId,
      rating,
      type,
      message,
      email || null,
      reportData ? JSON.stringify(reportData) : null
    );
    
    stmt.finalize();
    
    console.log(`✅ Feedback saved successfully for user ${userId}`);
    
    res.json({ 
      success: true, 
      message: 'Feedback submitted successfully. Thank you for your input!' 
    });
    
  } catch (error) {
    console.error('❌ Feedback submission error:', error);
    res.status(500).json({ 
      error: 'Failed to submit feedback. Please try again.' 
    });
  }
});

// ==========================================
// ERROR HANDLING & STARTUP
// ==========================================

// Global error handler
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down gracefully...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    } else {
      console.log('✅ Database connection closed');
    }
    process.exit(0);
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Local SEO Audit v3 (COMPLETE) running on http://localhost:${PORT}`);
  console.log('');
  console.log('🎯 COMPLETE VERSION - ALL FEATURES:');
  console.log('✅ Complete 12-factor scoring system (100 points)');
  console.log('✅ Outscraper integration with async polling');
  console.log('✅ ScrapingBee screenshot capture');
  console.log('✅ OpenAI screenshot analysis (posts, tiles, Q&A, social)');
  console.log('✅ Citation checking across 7 directories');
  console.log('✅ Website analysis (GBP embed + service extraction)');
  console.log('✅ SerpAPI reviews analysis');
  console.log('✅ AI-powered smart suggestions');
  console.log('✅ Complete action plan generation');
  console.log('✅ Production-ready error handling');
  console.log('');
  console.log('🔧 API STATUS:');
  console.log(`📍 Outscraper: ${OUTSCRAPER_API_KEY ? '✅ Ready' : '❌ Missing'}`);
  console.log(`📸 ScrapingBee: ${SCRAPINGBEE_API_KEY ? '✅ Ready' : '❌ Missing'}`);
  console.log(`🤖 OpenAI: ${OPENAI_API_KEY ? '✅ Ready' : '❌ Missing'}`);
  console.log(`🔍 SerpAPI: ${SERPAPI_KEY ? '✅ Ready' : '❌ Missing'}`);
  console.log('');
  console.log(`🏷️ Brand: ${BRAND_CONFIG.name}`);
  console.log(`💰 Estimated cost per report: ~$0.085`);
  console.log(`📈 Profit margin: 99.83% at $49/report`);
  console.log('');
  console.log('🚀 Ready for production deployment!');
});
