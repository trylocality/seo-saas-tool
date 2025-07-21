# SQLite to PostgreSQL Migration Notes

## Backup Information
- **Date**: 2025-07-21
- **Original File**: `server-v2.js` (SQLite version)
- **Backup File**: `server-v2-sqlite-backup.js`
- **Database Backup**: `seo_audit_v3.db` (36KB)

## Changes Made

### 1. Database Dependencies
- Added `pg` package for PostgreSQL support
- Keeping `sqlite3` for local development compatibility

### 2. Environment Variables
New environment variables needed:
- `DATABASE_URL`: PostgreSQL connection string (provided by Render)
- `NODE_ENV`: Set to 'production' on Render

### 3. Database Selection Logic
The app will use:
- PostgreSQL when `DATABASE_URL` is present (production)
- SQLite when no `DATABASE_URL` (local development)

### 4. Query Differences
Updated queries to handle both databases:
- `AUTOINCREMENT` → `SERIAL` (PostgreSQL)
- `?` placeholders → `$1, $2, $3` (PostgreSQL)
- Parameter binding differences

## Rollback Instructions

If you need to revert to SQLite-only:
1. Copy `server-v2-sqlite-backup.js` back to `server-v2.js`
2. Remove `pg` from package.json
3. Delete this migration notes file

## Render Setup

1. Create a PostgreSQL database on Render
2. It will provide a `DATABASE_URL` automatically
3. Add to your web service environment variables:
   - The `DATABASE_URL` from your database
   - `NODE_ENV=production`

## Testing

Local testing (SQLite):
```bash
npm start
```

Production testing (PostgreSQL):
```bash
DATABASE_URL="postgresql://user:pass@host:5432/dbname" npm start
```