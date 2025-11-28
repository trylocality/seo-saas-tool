# Dual-Source API Integration

## Overview

The SEO audit tool now uses **dual-source validation** by integrating both Outscraper and G Maps Extractor APIs. This provides better data coverage and validation for the 15 local SEO ranking factors.

## Integration Strategy

### Primary Source: Outscraper
- Photos count
- Posts data
- Reviews content
- Complete business data

### Secondary Source: G Maps Extractor
- **Description** (meta description from website)
- **Social media links** (better extraction)
- Tracking IDs (GA4, GTM, Facebook Pixel, LinkedIn)
- Verification validation

### Dual-Source Validation Logic

The system fetches data from both APIs in parallel and merges the results using these rules:

1. **Description Field:**
   - If Outscraper has description → use Outscraper (GBP description preferred)
   - If Outscraper empty + G Maps has description → use G Maps (meta description)
   - Logs both for debugging when both sources provide data

2. **Social Media Links:**
   - Compares count from both sources
   - Uses whichever has more social links
   - Merges both sources if available

3. **Verification Status:**
   - Cross-validates between both sources
   - If mismatch, trusts whichever says verified=true
   - Logs mismatches for debugging

4. **Basic Data Validation:**
   - Logs mismatches for phone, website, address
   - Keeps Outscraper as authoritative source
   - Uses G Maps data as validation/fallback

## Implementation Details

### New Function: `getGMapsExtractorData()`
**Location:** [server-v2.js:1246-1436](server-v2.js#L1246-L1436)

**Features:**
- 30-minute cache TTL (matches Outscraper)
- State-based coordinate lookup for 50 US states
- Extracts social links from arrays
- Parses tracking IDs from nested structure
- Returns null on failure (graceful degradation)

### Dual-Source Integration Point
**Location:** [server-v2.js:5073-5138](server-v2.js#L5073-L5138)

**Flow:**
1. Fetch Outscraper data (Step 1)
2. Fetch G Maps Extractor data (Step 1B)
3. Perform dual-source validation
4. Merge data into `partialData.outscraper`
5. Continue with screenshots and AI analysis

## Data Comparison

| Ranking Factor | Outscraper | G Maps Extractor | Winner |
|----------------|-----------|------------------|--------|
| Description | GBP description (often empty) | Website meta description | **G Maps** |
| Categories | ✅ Array or string | ✅ Comma-separated | Tie |
| Photos | ✅ photos_count | ❌ Only featured image | **Outscraper** |
| Reviews | ✅ reviews, rating | ✅ review_count, average_rating | Tie |
| Product Tiles | ❌ Not available | ❌ Not available | Neither |
| Posts | ✅ With extractContacts | ❌ Not available | **Outscraper** |
| Social Links | Basic object | ✅ Separate arrays | **G Maps** |
| Hours | ✅ Structured object | ✅ Formatted string | Tie |
| Address | ✅ full_address | ✅ full_address | Tie |
| Phone | ✅ phone | ✅ phone | Tie |
| Website | ✅ site | ✅ website, domain | Tie |
| Verified | ✅ verified/claimed | ✅ claimed (YES/NO) | Tie |
| Place ID | ✅ place_id, google_id | ✅ place_id | Tie |

## Environment Variables

Add to your `.env` file or Render environment variables:

```bash
GMAPSEXTRACTOR_KEY=your_api_key_here
```

**Note:** The API key is optional. If not configured, the system gracefully falls back to Outscraper-only mode.

## API Endpoints

### G Maps Extractor API
- **URL:** `https://cloud.gmapsextractor.com/api/v2/search`
- **Method:** POST
- **Auth:** Bearer token in Authorization header
- **Timeout:** 15 seconds
- **Cache:** 30 minutes

**Request Body:**
```javascript
{
  "q": "Business Name Location",
  "page": 1,
  "ll": "@latitude,longitude,11z",
  "hl": "en",
  "gl": "us",
  "extra": true  // Include social media links
}
```

**Response Structure:**
```javascript
{
  "total": 1,
  "data": [
    {
      "name": "Business Name",
      "full_address": "...",
      "categories": "Category1, Category2",
      "phone": "...",
      "claimed": "YES",
      "review_count": 1158,
      "average_rating": 4.2,
      "website": "...",
      "opening_hours": "...",
      "place_id": "...",
      "instagram_links": [],
      "linkedin_links": [],
      "twitter_links": [],
      "youtube_links": [],
      "facebook_links": [],
      "meta": {
        "title": "...",
        "description": "..."
      },
      "tracking_ids": {
        "google": { "ga4": "...", "gtm": "..." },
        "meta": { "pixelId": "..." },
        "linkedin": { "partnerId": "..." }
      }
    }
  ]
}
```

## Testing

### Test Files Created:
1. **test-gmaps-working.js** - Standalone G Maps Extractor test
2. **test-dual-source-vyde.js** - Dual-source validation test

### To Test on Production:
1. Deploy to Render with `GMAPSEXTRACTOR_KEY` environment variable
2. Run a full audit for any business
3. Check console logs for dual-source validation output
4. Look for these log messages:
   - `🗺️ Step 1B: Getting G Maps Extractor data for validation...`
   - `🔍 === DUAL-SOURCE VALIDATION ===`
   - Description merge/comparison logs
   - Social links comparison logs

## Console Output Example

```
📍 Step 1: Getting business data...
✅ Outscraper found: Vyde Tax & Accounting

🗺️ Step 1B: Getting G Maps Extractor data for validation...
✅ G Maps Extractor data retrieved successfully

🔍 === DUAL-SOURCE VALIDATION ===
   📝 Description: Using G Maps Extractor (Outscraper empty)
   🔗 Social Links: Using G Maps Extractor (4 vs 0)
   ✅ Verification: Both agree (true)
=================================
```

## Benefits

1. **Better Description Coverage:** G Maps provides meta descriptions when GBP descriptions are missing
2. **Improved Social Link Detection:** G Maps has superior social media extraction
3. **Cross-Validation:** Verify data accuracy between two independent sources
4. **Tracking Insights:** Access GA4, GTM, Facebook Pixel IDs for additional analysis
5. **Graceful Degradation:** Falls back to Outscraper-only if G Maps fails or isn't configured
6. **No Breaking Changes:** Existing functionality remains intact, G Maps is purely additive

## Future Enhancements

1. Add more state coordinates for international support
2. Use G Maps data to validate/correct Outscraper phone numbers
3. Store tracking IDs in audit reports for client insights
4. Implement weighted scoring based on data source reliability
5. Add third data source for triple validation (e.g., SerpAPI, Bright Data)
