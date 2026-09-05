# Private Chat — cloud-ready full starter

Recommended deployment: a Node-compatible paid/always-on cloud service with persistent disk/database.

This package includes:
- persistent SQLite users/messages/sessions/uploads when deployed with a persistent disk
- bcrypt password hashing
- Express sessions
- rate limiting + Helmet
- admin user creation/disable
- 1-to-1 real-time chat
- file upload (25 MB starter limit)
- WebRTC signaling for voice/video
- user-consented geolocation sharing
- Render Blueprint (`render.yaml`)

Environment variables:
ADMIN_USER
ADMIN_PASSWORD
SESSION_SECRET
INVITE_CODE
DB_PATH=/var/data/data.sqlite

IMPORTANT:
This is a strong starter, not a security-audited production messenger. For serious production use,
move to managed PostgreSQL/object storage, add a TURN server for reliable calls, antivirus/file scanning,
CSRF strategy, account recovery, 2FA, audit logs, backups, E2EE if required, and a formal security review.

The service must be deployed on HTTPS for browser camera/mic/location permissions and secure cookies.
Do not use a calculator/disguise as a security control.
