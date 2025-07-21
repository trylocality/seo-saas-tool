# PostgreSQL Setup for Render Deployment

## Current Status

Your app currently uses SQLite, which stores data in a local file (`seo_audit_v3.db`). This works great for local development, but on platforms like Render, the filesystem is ephemeral - meaning your database gets wiped on every deployment.

## Solution: PostgreSQL on Render

To preserve user data across deployments, you need to use Render's PostgreSQL database service.

## Setup Steps

### 1. Create a PostgreSQL Database on Render

1. Log into your Render dashboard
2. Click "New +" → "PostgreSQL"
3. Choose a name (e.g., "seo-tool-db")
4. Select the free tier
5. Click "Create Database"
6. Wait for it to provision (takes a few minutes)

### 2. Get Your Database URL

1. Once created, click on your database
2. Copy the "External Database URL" (starts with `postgresql://`)
3. Keep this secure - it contains your database credentials

### 3. Add Database URL to Your Web Service

1. Go to your web service on Render
2. Click "Environment" in the left sidebar
3. Add a new environment variable:
   - Key: `DATABASE_URL`
   - Value: (paste your PostgreSQL URL from step 2)
4. Click "Save Changes"

### 4. Update Your Code

I've created a `database-adapter.js` file that automatically:
- Uses PostgreSQL when `DATABASE_URL` is present (production)
- Uses SQLite when no `DATABASE_URL` (local development)

To use it, you'll need to update your `server-v2.js` file. The main changes are:

1. Replace SQLite initialization with the adapter
2. Update SQL queries to use `$1, $2` instead of `?` for parameters
3. Convert callbacks to async/await

### 5. Test Locally

You can test PostgreSQL locally by:

1. Installing PostgreSQL on your machine
2. Creating a local database
3. Setting DATABASE_URL in your .env file:
   ```
   DATABASE_URL=postgresql://localhost:5432/seo_tool_dev
   ```

### 6. Deploy

Once everything is set up:
1. Commit and push your changes
2. Render will automatically deploy
3. Your app will now use PostgreSQL and preserve data!

## Important Notes

- The first deployment with PostgreSQL will start with an empty database
- Existing SQLite data won't be migrated automatically
- You can manually export/import data if needed

## Backup Plan

If you need to revert:
- Use `server-v2-sqlite-backup.js` (your original file)
- Remove the `DATABASE_URL` environment variable
- Redeploy

## Need Help?

The database adapter handles most of the complexity. The main thing you need to do is update the SQL queries in your server file to use the new parameter style ($1, $2 instead of ?).