# Secure Workspace — deployable private messenger starter

This version replaces the calculator-like UI with a real messenger layout and fixes the main live-use issues from the earlier starter.

## Included
- Real sidebar messenger UI with online/offline indicators and last-seen state.
- Reliable Socket.IO message delivery with acknowledgement + REST fallback endpoint.
- Persistent SQLite users, messages, sessions and uploads when `/var/data` is mounted.
- bcrypt password hashing and secure session cookies in production.
- Admin: create/disable users, see online state, last login, last seen, IP and browser/OS device label.
- Admin conversation monitor: select any two users and read their stored 1-to-1 conversation.
- Message popup/toast notifications when a new message arrives outside the open conversation.
- Voice/video call UI with WebRTC signaling and incoming-call prompt.
- File uploads up to 25 MB.
- No location-sharing button or covert browser geolocation tracking.
- Opaque private access path derived from `SESSION_SECRET`; the root URL intentionally returns 404.
- Render Blueprint with persistent disk.

## Important access-path behavior
The app is deliberately not exposed at `/`. On startup it derives a random-looking path from `SESSION_SECRET`, for example `/a91...`. The exact path is printed in the server log as `ACCESS_PATH=/...`.

If `SESSION_SECRET` stays the same, the access path stays the same. Do not change it after deployment unless you intentionally want a new private URL.

This hides the app behind an unguessable path; it is not encryption and should not be treated as a security boundary. Keep authentication enabled.

## Render setup
Set these environment variables:
- `ADMIN_USER`
- `ADMIN_PASSWORD` (strong password)
- `INVITE_CODE` (strong random registration code)
- `SESSION_SECRET` (Render Blueprint generates this)
- `NODE_ENV=production`
- `DATA_DIR=/var/data`

The Blueprint creates a 1 GB persistent disk at `/var/data`.

## Local run
```bash
npm install
ADMIN_USER=admin ADMIN_PASSWORD='change-this' INVITE_CODE='invite-this' SESSION_SECRET='long-random-secret' npm start
```
Open the `ACCESS_PATH` printed in the terminal.

## Calls
Voice/video uses WebRTC. A public STUN server is included for basic NAT traversal. For reliable production calls across restrictive networks, configure a TURN server and add its credentials to the `RTCPeerConnection` iceServers list.

## Security notes
This is a substantially stronger deployable starter, not a formally audited end-to-end-encrypted messenger. For a high-security deployment, add managed PostgreSQL/object storage, backups, antivirus scanning, CSRF protection for state-changing REST routes, 2FA, audit logging, TURN, stronger account recovery controls, and a security review.
