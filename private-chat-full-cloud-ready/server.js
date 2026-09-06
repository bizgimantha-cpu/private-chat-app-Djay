const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const multer = require('multer');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 1e6 });
const PORT = process.env.PORT || 8080;
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const dbPath = process.env.DB_PATH || path.join(dataDir, 'data.sqlite');
const db = new sqlite3.Database(dbPath);
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'CHANGE_ME_NOW';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const INVITE_CODE = process.env.INVITE_CODE || 'CHANGE_ME_NOW';
const ACCESS_PATH = process.env.ACCESS_PATH || crypto.createHash('sha256').update(SESSION_SECRET + ':private-workspace').digest('hex').slice(0, 28);
const APP_BASE = '/' + ACCESS_PATH;
const socketTokens = new Map();
const sockets = new Map(); // username -> Set(socket ids)

function q(sql, p = []) { return new Promise((res, rej) => db.all(sql, p, (e, r) => e ? rej(e) : res(r))); }
function one(sql, p = []) { return new Promise((res, rej) => db.get(sql, p, (e, r) => e ? rej(e) : res(r))); }
function run(sql, p = []) { return new Promise((res, rej) => db.run(sql, p, function (e) { e ? rej(e) : res(this); })); }
function userOnline(username) { return !!sockets.get(username)?.size; }
function safeUser(u) { return { username: u.username, displayName: u.display_name || u.username, disabled: !!u.disabled, online: userOnline(u.username), lastSeenAt: u.last_seen_at || null, lastLoginAt: u.last_login_at || null, ip: u.last_ip || null, device: u.device || null }; }
function getClientIp(req) { return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim(); }
function deviceLabel(ua = '') {
  const s = String(ua);
  const browser = /Edg\//.test(s) ? 'Edge' : /Chrome\//.test(s) ? 'Chrome' : /Firefox\//.test(s) ? 'Firefox' : /Safari\//.test(s) && !/Chrome\//.test(s) ? 'Safari' : /OPR\//.test(s) ? 'Opera' : 'Browser';
  const os = /Windows NT/.test(s) ? 'Windows' : /Mac OS X/.test(s) ? 'macOS' : /Android/.test(s) ? 'Android' : /iPhone|iPad/.test(s) ? 'iOS' : /Linux/.test(s) ? 'Linux' : 'Unknown OS';
  return `${browser} · ${os}`;
}
function requireAppPath(req, res, next) {
  if (req.path === APP_BASE || req.path.startsWith(APP_BASE + '/')) return next();
  if (req.path === '/socket.io' || req.path === '/api/health') return next();
  return res.status(404).send('Not found');
}

(async () => {
  await run(`CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,display_name TEXT,disabled INTEGER DEFAULT 0,created_at INTEGER,last_login_at INTEGER,last_seen_at INTEGER,last_ip TEXT,device TEXT)`);
  await run(`CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY,from_user TEXT NOT NULL,to_user TEXT NOT NULL,text TEXT,created_at INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS uploads(id TEXT PRIMARY KEY,user TEXT,filename TEXT,stored TEXT,created_at INTEGER)`);
  // Backward-compatible columns for databases made by the earlier starter.
  for (const c of ['last_login_at INTEGER','last_seen_at INTEGER','last_ip TEXT','device TEXT']) {
    try { await run(`ALTER TABLE users ADD COLUMN ${c}`); } catch (_) {}
  }
  console.log(`Private workspace path: ${APP_BASE}`);
})().catch(err => console.error('DB init failed', err));

db.run('PRAGMA journal_mode=WAL');
db.run('PRAGMA foreign_keys=ON');

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: new SQLiteStore({ db: path.basename(path.join(dataDir, 'sessions.sqlite')), dir: dataDir }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 500, standardHeaders: true, legacyHeaders: false }));

const uploadDir = path.join(dataDir, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({ dest: uploadDir, limits: { fileSize: 25 * 1024 * 1024 } });

app.get('/api/health', (req, res) => res.json({ ok: true }));

function auth(req, res, next) { if (!req.session.user) return res.status(401).json({ error: 'Login required' }); next(); }
function admin(req, res, next) { if (req.session.user?.role !== 'admin') return res.status(403).json({ error: 'Admin only' }); next(); }

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const name = String(username || '').trim();
    const ip = getClientIp(req);
    const device = deviceLabel(req.headers['user-agent']);
    if (name === ADMIN_USER && password === ADMIN_PASSWORD && ADMIN_PASSWORD !== 'CHANGE_ME_NOW') {
      req.session.user = { username: ADMIN_USER, role: 'admin', displayName: 'Administrator' };
      return req.session.save(() => res.json({ ok: true, user: req.session.user }));
    }
    const u = await one('SELECT * FROM users WHERE username=?', [name]);
    if (!u || u.disabled || !(await bcrypt.compare(String(password || ''), u.password_hash))) return res.status(401).json({ error: 'Invalid login' });
    const now = Date.now();
    await run('UPDATE users SET last_login_at=?,last_seen_at=?,last_ip=?,device=? WHERE username=?', [now, now, ip, device, u.username]);
    req.session.user = { username: u.username, role: 'user', id: u.id, displayName: u.display_name || u.username };
    req.session.save(() => res.json({ ok: true, user: req.session.user }));
  } catch (e) { console.error(e); res.status(500).json({ error: 'Login failed' }); }
});

app.get('/api/me', auth, async (req, res) => res.json({ user: req.session.user, appPath: APP_BASE }));
app.get('/api/socket-token', auth, (req, res) => {
  const t = crypto.randomBytes(32).toString('hex');
  socketTokens.set(t, { user: req.session.user, expires: Date.now() + 60000 });
  res.json({ token: t });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/users', auth, async (req, res) => {
  let rows = await q('SELECT username,display_name,disabled,last_login_at,last_seen_at,last_ip,device FROM users ORDER BY username COLLATE NOCASE');
  if (req.session.user.role !== 'admin') rows = rows.filter(x => x.username !== req.session.user.username && !x.disabled);
  res.json(rows.map(safeUser));
});

app.post('/api/users', auth, admin, async (req, res) => {
  const { username, password, displayName } = req.body || {};
  const name = String(username || '').trim();
  if (!/^[a-zA-Z0-9_.-]{2,40}$/.test(name) || String(password || '').length < 8) return res.status(400).json({ error: 'Username must be 2-40 characters and password at least 8 characters.' });
  try {
    await run('INSERT INTO users(id,username,password_hash,display_name,disabled,created_at) VALUES(?,?,?,?,?,?)', [crypto.randomUUID(), name, await bcrypt.hash(String(password), 12), String(displayName || name).trim(), 0, Date.now()]);
    res.json({ ok: true });
  } catch (e) { res.status(409).json({ error: 'Username already exists' }); }
});

app.patch('/api/users/:username', auth, admin, async (req, res) => {
  await run('UPDATE users SET disabled=? WHERE username=?', [req.body.disabled ? 1 : 0, req.params.username]);
  res.json({ ok: true });
});

app.post('/api/invite/register', async (req, res) => {
  const { inviteCode, username, password, displayName } = req.body || {};
  if (!INVITE_CODE || INVITE_CODE === 'CHANGE_ME_NOW' || inviteCode !== INVITE_CODE) return res.status(403).json({ error: 'Invalid invite' });
  const name = String(username || '').trim();
  if (!/^[a-zA-Z0-9_.-]{2,40}$/.test(name) || String(password || '').length < 8) return res.status(400).json({ error: 'Invalid username or password' });
  try {
    await run('INSERT INTO users(id,username,password_hash,display_name,disabled,created_at) VALUES(?,?,?,?,?,?)', [crypto.randomUUID(), name, await bcrypt.hash(String(password), 12), String(displayName || name).trim(), 0, Date.now()]);
    res.json({ ok: true });
  } catch (e) { res.status(409).json({ error: 'Username already exists' }); }
});

app.get('/api/messages/:peer', auth, async (req, res) => {
  const me = req.session.user.username, peer = String(req.params.peer);
  if (req.session.user.role !== 'admin' && peer === me) return res.status(400).json({ error: 'Invalid peer' });
  const rows = await q('SELECT id,from_user fromUser,to_user toUser,text,created_at createdAt FROM messages WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?) ORDER BY created_at ASC LIMIT 500', [me, peer, peer, me]);
  res.json(rows);
});

app.get('/api/admin/messages/:a/:b', auth, admin, async (req, res) => {
  const a = String(req.params.a), b = String(req.params.b);
  const rows = await q('SELECT id,from_user fromUser,to_user toUser,text,created_at createdAt FROM messages WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?) ORDER BY created_at ASC LIMIT 1000', [a,b,b,a]);
  res.json(rows);
});

app.post('/api/messages', auth, async (req, res) => {
  const to = String(req.body?.to || '').trim();
  const text = String(req.body?.text || '').trim().slice(0, 10000);
  if (!to || !text || to === req.session.user.username) return res.status(400).json({ error: 'Invalid message' });
  const target = await one('SELECT username,disabled FROM users WHERE username=?', [to]);
  if (!target || target.disabled) return res.status(404).json({ error: 'User not available' });
  const id = crypto.randomUUID(), ts = Date.now();
  await run('INSERT INTO messages VALUES(?,?,?,?,?)', [id, req.session.user.username, to, text, ts]);
  const msg = { id, fromUser: req.session.user.username, toUser: to, text, createdAt: ts };
  emitUser(to, 'chat:message', msg);
  emitUser(req.session.user.username, 'chat:message', msg);
  res.json(msg);
});

app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const id = crypto.randomUUID();
  const ext = path.extname(req.file.originalname).slice(0, 12).replace(/[^a-zA-Z0-9.]/g, '');
  const stored = id + ext;
  fs.renameSync(req.file.path, path.join(uploadDir, stored));
  await run('INSERT INTO uploads VALUES(?,?,?,?,?)', [id, req.session.user.username, req.file.originalname, stored, Date.now()]);
  res.json({ id, url: `${APP_BASE}/files/${stored}`, filename: req.file.originalname });
});

app.get(APP_BASE + '/files/:name', auth, (req, res) => res.sendFile(path.join(uploadDir, path.basename(req.params.name))));

function emitUser(username, event, payload) {
  for (const id of sockets.get(username) || []) io.to(id).emit(event, payload);
}
function broadcastPresence(username, online) { io.emit('presence:update', { username, online }); }

io.use((s, next) => {
  const t = s.handshake.auth?.token, v = socketTokens.get(t);
  if (!v || v.expires < Date.now()) return next(new Error('unauthorized'));
  socketTokens.delete(t);
  s.data.user = v.user;
  next();
});

io.on('connection', async s => {
  const username = s.data.user.username;
  if (!sockets.has(username)) sockets.set(username, new Set());
  sockets.get(username).add(s.id);
  await run('UPDATE users SET last_seen_at=? WHERE username=?', [Date.now(), username]).catch(() => {});
  broadcastPresence(username, true);

  s.on('presence:heartbeat', async () => {
    await run('UPDATE users SET last_seen_at=? WHERE username=?', [Date.now(), username]).catch(() => {});
  });
  s.on('chat:send', async (m, ack) => {
    try {
      const to = String(m?.to || '').trim(), text = String(m?.text || '').trim().slice(0, 10000);
      if (!to || !text || to === username) throw new Error('Invalid message');
      const target = await one('SELECT username,disabled FROM users WHERE username=?', [to]);
      if (!target || target.disabled) throw new Error('User not available');
      const id = crypto.randomUUID(), ts = Date.now();
      await run('INSERT INTO messages VALUES(?,?,?,?,?)', [id, username, to, text, ts]);
      const msg = { id, fromUser: username, toUser: to, text, createdAt: ts };
      emitUser(to, 'chat:message', msg);
      emitUser(username, 'chat:message', msg);
      if (typeof ack === 'function') ack({ ok: true, message: msg });
    } catch (e) { if (typeof ack === 'function') ack({ ok: false, error: e.message }); }
  });
  s.on('call:signal', m => {
    const to = String(m?.to || '');
    if (to) emitUser(to, 'call:signal', { from: username, data: m.data });
  });
  s.on('disconnect', async () => {
    const set = sockets.get(username);
    if (set) {
      set.delete(s.id);
      if (!set.size) { sockets.delete(username); broadcastPresence(username, false); }
    }
    await run('UPDATE users SET last_seen_at=? WHERE username=?', [Date.now(), username]).catch(() => {});
  });
});

// Only the opaque access path exposes the application UI. Root deliberately stays generic.
app.get(APP_BASE, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use(APP_BASE, express.static(path.join(__dirname, 'public')));

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Private workspace running on port ${PORT}`);
  console.log(`ACCESS_PATH=${APP_BASE}`);
});
