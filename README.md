# Dropbox Backend

## Deployment email setup

The app sends password-reset codes and account/payment notifications using Gmail SMTP. Configure these variables in the hosting provider's environment-variable settings:

- `SMTP_EMAIL`: the Gmail sender address
- `SMTP_APP_PASSWORD`: a Google App Password, not the normal Gmail password
- `ADMIN_EMAIL`: optional recipient for contact form messages; defaults to `SMTP_EMAIL`

Redeploy or restart the service after setting both values. Do not commit `.env`; it is ignored by Git.

To check the deployed SMTP connection, sign in as an admin and request `GET /api/admin/email-status`. A successful response reports `configured: true` and `connected: true`. A `503` response means the variables are missing or Gmail rejected them; check the deployment logs and provider settings.

Users must have valid, reachable email addresses to receive messages.

Avatar images are stored in `public/uploads` and user records remain in memory, matching the existing demo storage model. For multi-instance production deployments, replace local uploads with persistent object storage.