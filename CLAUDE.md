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

## Subscription Cancellation System

The application now includes a subscription cancellation feature accessible from the billing history modal.

### How it works:
1. **Access**: Users click "CANCEL" link in billing history modal
2. **Form**: Cancellation form asks for reason and optional feedback
3. **Processing**: Subscription is cancelled, credits set to 0, user reverted to free tier
4. **Notifications**: Console logging and optional webhook for cancellation tracking

### Current Setup:
- **Cancellation endpoint**: `POST /api/cancel-subscription`
- **Console Logging**: All cancellations are logged to server console
- **Database Update**: User's subscription_tier set to 'free', credits_remaining set to 0
- **Optional Webhook**: Configure `CANCELLATION_WEBHOOK_URL` in .env

### Webhook Configuration (Optional):
To receive cancellation notifications via webhook:
1. Add to .env file:
   ```
   CANCELLATION_WEBHOOK_URL=https://hooks.zapier.com/hooks/catch/your-webhook-id
   ```
2. Webhook receives:
   - User details (ID, email, name, previous plan, credits lost)
   - Cancellation details (reason, feedback, timestamp)

### Cancellation Reasons:
- Too expensive
- Not using the service
- Missing features I need
- Found a better alternative
- Too many technical issues
- Other reason

### Testing:
- Test cancellation flow from billing history
- Check server console for cancellation logs
- Verify user is reverted to free tier

## Bulk Audit Completion Email Notifications

The application now sends email notifications to users when their bulk audits are complete.

### How it works:
1. **Automatic Trigger**: Email is sent immediately after a bulk audit finishes processing
2. **User Notification**: Users receive a summary of their completed bulk audit
3. **Console Logging**: All notifications are logged to server console
4. **Optional Webhook**: Can be configured to send emails via webhook services

### Current Setup:
- **Endpoint**: `/api/generate-fast-bulk-scan`
- **Email Function**: `sendBulkAuditCompleteEmail()`
- **Trigger**: Automatically called after bulk audit completes
- **Test Endpoint**: `POST /api/test/bulk-audit-complete`

### Email Content Includes:
- User's name
- Industry and location scanned
- Number of businesses analyzed
- Average SEO score
- Credits used
- Completion timestamp
- Link to view the report in dashboard

### Webhook Configuration (Optional):
To enable email delivery via webhook:
1. Add to .env file:
   ```
   BULK_AUDIT_WEBHOOK_URL=https://hooks.zapier.com/hooks/catch/your-webhook-id
   ```
2. The system will automatically use this webhook to send emails
3. Fallback webhooks: `EMAIL_WEBHOOK_URL` → `FEEDBACK_WEBHOOK_URL`

### Example Zapier Setup:
1. Go to zapier.com
2. Create new Zap: "Webhooks by Zapier" → "Gmail" or "Email by Zapier"
3. Set trigger to "Catch Hook"
4. Copy webhook URL to .env file
5. Configure email action:
   - To: `{{userEmail}}`
   - Subject: `{{subject}}`
   - Body: `{{html}}` (for HTML) or `{{text}}` (for plain text)
6. Add filter: Only continue if `emailType` = `bulk_audit_complete`
7. Test and activate

### Testing:
- Use test endpoint: `POST /api/test/bulk-audit-complete`
- Required fields: `industry`, `location`
- Optional field: `businessesScanned` (defaults to 10)
- Check server console for email notifications
- Example test request:
  ```json
  {
    "industry": "restaurants",
    "location": "Chicago, IL",
    "businessesScanned": 15
  }
  ```

### Data Structure:
The webhook receives:
```json
{
  "to": "user@example.com",
  "subject": "✅ Your Bulk Audit is Complete - 10 Businesses Analyzed",
  "html": "HTML email content",
  "text": "Plain text email content",
  "type": "bulk_audit_complete",
  "emailType": "bulk_audit_complete",
  "timestamp": "2025-10-05T12:34:56.789Z"
}
```