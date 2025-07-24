# Single Zap with Paths Setup

Since you're using one Zap with different paths based on the `type` field, you only need one webhook URL!

## Environment Setup

Add this to your `.env` file:

```env
# Single webhook URL for all email notifications
EMAIL_WEBHOOK_URL=https://hooks.zapier.com/hooks/catch/23916813/uudm9dj/

# Keep the feedback one as backup/fallback
FEEDBACK_WEBHOOK_URL=https://hooks.zapier.com/hooks/catch/23916813/uudm9dj/
```

## Zapier Path Configuration

In your Zapier Zap, set up paths based on the `type` field:

### Path 1: New User Notification
- **Filter**: `type` equals `new_user`
- **Action**: Send email to admin
- **Data to use**:
  - Subject: `subject`
  - Body: `body`
  - Additional data in: `data` object

### Path 2: Email Verification
- **Filter**: `type` equals `email_verification`
- **Action**: Send email to user
- **Data to use**:
  - To: `to`
  - Subject: `subject`
  - HTML Body: `html`
  - Text Body: `text`

### Path 3: Password Reset
- **Filter**: `type` equals `password_reset`
- **Action**: Send email to user
- **Data to use**:
  - To: `to`
  - Subject: `subject`
  - HTML Body: `html`
  - Text Body: `text`

### Path 4: Feedback Submission
- **Filter**: `type` equals `feedback_submission`
- **Action**: Send email to admin
- **Data to use**:
  - To: `to` (or hardcode trylocality@gmail.com)
  - Subject: `subject`
  - Body: `body`
  - Feedback details in: `feedbackData` object

## All Webhook Data Now Includes:

Every webhook now sends these fields:
- `type` - The webhook type for path filtering
- `emailType` - Same as type (for backwards compatibility)
- `timestamp` - When the webhook was triggered

## Testing Your Paths

1. **Test New User**: Sign up for a new account
2. **Test Email Verification**: Sign up or request verification resend
3. **Test Password Reset**: Use "Forgot Password" on login page
4. **Test Feedback**: Submit feedback from a report

Check your Zapier task history to see which path each webhook takes.

## Type Values for Path Filters:
- `new_user` - New user signup
- `email_verification` - Email verification
- `password_reset` - Password reset request
- `feedback_submission` - Feedback submitted