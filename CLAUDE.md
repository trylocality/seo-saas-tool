# SEO SaaS Tool - Development Notes

## Admin Dashboard & User Tracking

The application now includes comprehensive user tracking and admin features.

### Admin Dashboard Access:
- **URL**: `/admin.html`
- **Login**: Use trylocality@gmail.com account
- **Features**:
  - View all registered users
  - See user statistics (total users, paid users, reports generated)
  - Export user data to CSV
  - Track new signups (7-day and 30-day metrics)

### New User Notifications:
1. **Console Logging**: All new signups are logged to server console with full details
2. **Webhook Support**: Configure `NEW_USER_WEBHOOK_URL` in .env to receive notifications
3. **Data Included**:
   - User name and email
   - Signup date and time
   - Initial plan and credits
   - User ID

### API Endpoints:
- `GET /api/admin/users` - Get all users (requires admin auth)
- `GET /api/admin/users/export` - Download users as CSV
- `GET /api/admin/analytics` - Get user statistics

### CSV Export Format:
The exported CSV includes:
- User ID
- Email
- First Name, Last Name
- Credits Remaining
- Subscription Tier
- Number of Reports Generated
- Join Date

### Security:
- Only trylocality@gmail.com can access admin features
- All admin endpoints require authentication
- Consider implementing proper role-based access control for production

## Email Feedback System

The application now includes an email notification system for user feedback submissions.

### How it works:
1. **Frontend**: Users submit feedback via the "Share Feedback" button
2. **Backend**: Feedback is saved to SQLite database and email notification is triggered
3. **Console Logging**: All feedback notifications are logged to server console for immediate viewing
4. **Optional Webhook**: Can be configured to send emails via webhook services

### Current Setup:
- **Feedback endpoint**: `POST /api/feedback`
- **Email function**: `sendFeedbackEmail()`
- **Target email**: trylocality@gmail.com
- **Database**: Feedback stored in `feedback` table

### To enable email delivery:

#### Option 1: Console Monitoring (Currently Active)
- All feedback appears in server console logs
- Look for "=� FEEDBACK EMAIL NOTIFICATION" messages
- Includes full feedback details, user info, and timestamps

#### Option 2: Webhook Setup (Optional)
1. Create a webhook at Zapier, n8n, or similar service
2. Configure the webhook to send emails to trylocality@gmail.com
3. Add webhook URL to .env file:
   ```
   FEEDBACK_WEBHOOK_URL=https://hooks.zapier.com/hooks/catch/your-webhook-id
   ```

### Example Zapier Setup:
1. Go to zapier.com
2. Create new Zap: "Webhooks by Zapier" � "Gmail"
3. Use webhook URL in .env file
4. Configure email template with feedback data
5. Test and activate

### Feedback Data Structure:
```json
{
  "rating": 1-5,
  "type": "general|bug|feature|performance", 
  "message": "User feedback text",
  "email": "user@example.com (optional)",
  "reportData": {
    "businessName": "...",
    "location": "...", 
    "industry": "..."
  },
  "userId": 123,
  "userName": "User Name"
}
```

### Testing:
- Submit feedback via the UI
- Check server console for email notifications
- Verify feedback is saved in database