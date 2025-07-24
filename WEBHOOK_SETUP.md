# Webhook Setup Documentation

## Current Issue
Only the `NEW_USER_WEBHOOK_URL` is working because the other webhooks are not properly configured in the `.env` file.

## Required Webhook URLs in .env file

Add these to your `.env` file:

```env
# Email Verification Webhook
EMAIL_VERIFICATION_WEBHOOK_URL=https://hooks.zapier.com/hooks/catch/YOUR_ZAPIER_ID/YOUR_WEBHOOK_ID/

# Password Reset Webhook  
PASSWORD_RESET_WEBHOOK_URL=https://hooks.zapier.com/hooks/catch/YOUR_ZAPIER_ID/YOUR_WEBHOOK_ID/

# Feedback Submission Webhook (already exists)
FEEDBACK_WEBHOOK_URL=https://hooks.zapier.com/hooks/catch/23916813/uudm9dj/

# New User Alert Webhook
NEW_USER_WEBHOOK_URL=https://hooks.zapier.com/hooks/catch/YOUR_ZAPIER_ID/YOUR_WEBHOOK_ID/

# Generic Email Webhook (optional - used as fallback for email verification and password reset)
EMAIL_WEBHOOK_URL=https://hooks.zapier.com/hooks/catch/YOUR_ZAPIER_ID/YOUR_WEBHOOK_ID/
```

## Data Structure for Each Webhook

### 1. Email Verification Webhook
**Triggered when**: New user signs up or requests verification email resend
**Webhook URL env variable**: `EMAIL_VERIFICATION_WEBHOOK_URL` or `EMAIL_WEBHOOK_URL` (fallback)

```json
{
  "to": "user@example.com",
  "subject": "Verify your email - Locality",
  "html": "<div>...HTML content with verification link...</div>",
  "text": "Plain text version of the email",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

Key fields for Zapier:
- `to`: Recipient email address
- `subject`: Email subject line
- `html`: HTML formatted email content (includes verification link)
- `text`: Plain text version
- Verification URL is embedded in both html and text fields

### 2. Password Reset Webhook
**Triggered when**: User requests password reset
**Webhook URL env variable**: `PASSWORD_RESET_WEBHOOK_URL` or `EMAIL_WEBHOOK_URL` (fallback)

```json
{
  "to": "user@example.com",
  "subject": "Reset your password - Locality",
  "html": "<div>...HTML content with reset link...</div>",
  "text": "Plain text version with reset link",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

Key fields for Zapier:
- `to`: Recipient email address
- `subject`: Email subject line
- `html`: HTML formatted email content (includes reset link)
- `text`: Plain text version
- Reset URL is embedded in both html and text fields

### 3. Feedback Submission Webhook
**Triggered when**: User submits feedback
**Webhook URL env variable**: `FEEDBACK_WEBHOOK_URL`

```json
{
  "to": "trylocality@gmail.com",
  "subject": "🔔 New Feedback Submission - 4/5 stars",
  "body": "New feedback received from SEO Audit Tool:\n\n👤 User Information:...",
  "feedbackData": {
    "rating": 4,
    "type": "general",
    "message": "Great tool!",
    "email": "user@example.com",
    "reportData": {
      "businessName": "Test Business",
      "location": "Denver, CO",
      "industry": "Restaurant"
    },
    "userId": 123,
    "userName": "John Doe"
  }
}
```

Key fields for Zapier:
- `to`: Always "trylocality@gmail.com"
- `subject`: Includes rating
- `body`: Full formatted feedback text
- `feedbackData`: Structured feedback information

### 4. New User Alert Webhook (WORKING)
**Triggered when**: New user signs up
**Webhook URL env variable**: `NEW_USER_WEBHOOK_URL` or `FEEDBACK_WEBHOOK_URL` (fallback)

```json
{
  "subject": "🎉 New User Signup - user@example.com",
  "body": "New user registered on SEO Audit Tool:\n\n👤 User Information:...",
  "type": "new_user",
  "data": {
    "userId": 123,
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "signupDate": "2024-01-15T10:30:00.000Z",
    "plan": "free",
    "initialCredits": 1
  },
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

Key fields for Zapier:
- `subject`: Email subject with user email
- `body`: Full formatted notification text
- `type`: Always "new_user"
- `data`: Structured user information

## Zapier Configuration Guide

### For Email Webhooks (Verification & Password Reset):
1. Create a new Zap with "Webhooks by Zapier" trigger
2. Choose "Catch Hook" event
3. Copy the webhook URL to your .env file
4. In the Action step, choose "Gmail" or your email service
5. Map the fields:
   - To: `to`
   - Subject: `subject`
   - Body Type: HTML
   - Body: `html`

### For Feedback Webhook:
1. Create a new Zap with "Webhooks by Zapier" trigger
2. Choose "Catch Hook" event
3. Copy the webhook URL to your .env file
4. In the Action step, choose "Gmail" or your email service
5. Map the fields:
   - To: `to` (or hardcode "trylocality@gmail.com")
   - Subject: `subject`
   - Body: `body`

### For New User Alert:
1. Create a new Zap with "Webhooks by Zapier" trigger
2. Choose "Catch Hook" event
3. Copy the webhook URL to your .env file
4. In the Action step, choose "Gmail" or your email service
5. Map the fields:
   - To: Your admin email
   - Subject: `subject`
   - Body: `body`

## Troubleshooting

1. **Check server logs**: All webhooks log to console when triggered
2. **Verify .env file**: Make sure webhook URLs are properly set
3. **Test webhooks**: Use the test functionality in Zapier
4. **Check network**: Ensure your server can reach Zapier's servers
5. **Timeout issues**: Webhooks have a 5-second timeout

## Testing Each Webhook

### Test Email Verification:
1. Sign up for a new account
2. Check server logs for "📧 EMAIL NOTIFICATION"
3. Check Zapier webhook history

### Test Password Reset:
1. Go to login page and click "Forgot Password"
2. Enter a valid email
3. Check server logs and Zapier

### Test Feedback:
1. Generate a report and click feedback button
2. Submit feedback
3. Check server logs and Zapier

### Test New User Alert:
1. Sign up for a new account
2. Check server logs for "🎉 NEW USER NOTIFICATION"
3. Check Zapier webhook history