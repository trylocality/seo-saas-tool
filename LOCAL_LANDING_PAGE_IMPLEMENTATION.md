# Local Landing Page Implementation for Bulk Audits

## Summary
Successfully replaced "Services" with "Local Landing Page" detection as Factor #8 in bulk audits.

## What Changed

### Before:
- **Factor 8**: Services (from SerpAPI Google Maps)
- **Problem**: SerpAPI place lookups frequently fail with "Google failed to retrieve HTML" errors
- **Result**: Many businesses scored 0 for this factor

### After:
- **Factor 8**: Local Landing Page (from website analysis)
- **Detection**: Scans business website for location-specific pages
- **Benefit**: More reliable, controllable by businesses, stronger local SEO signal

## Implementation Details

### Changes Made:

1. **Step 4 in `generateFastBulkReport` (Line 3535)**
   - Replaced SerpAPI services extraction with website analysis
   - Calls `analyzeWebsite(website, location)` for each business
   - Gracefully handles businesses without websites

2. **Eight Factors Object (Line 3627)**
   - Removed: `services` object with count/serviceOptions
   - Added: `localLandingPage` object with hasPage/hasGBPEmbed

3. **Core Metrics (Line 3734)**
   - Removed: `servicesCount`, `meetsServicesReq`
   - Added: `hasLocalLandingPage`, `meetsLocalLandingPageReq`, `hasGBPEmbed`

4. **AI Comparison (Line 5170)**
   - Updated comparison prompt to show "Local Landing Page" instead of "Q&A"
   - AI now recommends local landing page improvements

5. **Data Compilation (Line 3669)**
   - Website analysis now properly included in bulk reports
   - Data flows through to frontend correctly

## What Gets Detected

The `analyzeWebsite` function detects:

### Location Directory Structures:
- `/locations/`, `/service-areas/`, `/cities/`
- `/areas/`, `/serving/`, `/coverage/`

### City-Specific URLs:
- `/miami/`, `/miami-plumber/`, `/miami-service/`
- `/locations/miami/`, `/service-area/miami/`

### State-Based Pages:
- `/florida/`, `/locations/florida/`

### Common Patterns:
- `provo-custom-home-builder`
- `miami-residential-contractor`

## Performance Impact

- **Per Business**: +2-5 seconds (website fetch + analysis)
- **10 Businesses**: +20-50 seconds total
- **With Parallel Processing**: Can be optimized to +10-30 seconds

## Benefits

✅ **More Reliable**: No longer dependent on SerpAPI place lookups  
✅ **Actionable**: Businesses can create landing pages to improve score  
✅ **Stronger Signal**: Local landing pages are proven ranking factors  
✅ **Better Data**: Website analysis already works well in regular audits  
✅ **Cost Effective**: Uses existing code, no additional API costs  

## Testing

The implementation:
- Handles businesses without websites gracefully
- Falls back to empty data if website analysis fails
- Logs clear status for debugging (✅/❌)
- Maintains backward compatibility with frontend

## Frontend Display

The bulk audit frontend should now show:
- ✅/❌ for "Local Landing Page" presence
- Recommendation to create location-specific pages if missing
- AI comparison includes landing page analysis
