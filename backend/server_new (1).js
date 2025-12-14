// server.js - Indian Finder backend (Railway)
// Uploads + X OAuth2 + tweet-to-community helper

const express = require('express');
const cors = require('cors');
const session = require('express-session');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

// ---------- Env ----------
const PORT = process.env.PORT || 3000;

// Public site origin (Netlify) so cookies can work cross-site
const PUBLIC_SITE_URL = process.env.PUBLIC_SITE_URL || '';
// For OAuth callback (must match X developer portal exactly)
const X_REDIRECT_URI = process.env.X_REDIRECT_URI || process.env.X_REDIRECT_URL || '';
const X_CLIENT_ID = process.env.X_CLIENT_ID || '';
const X_CLIENT_SECRET = process.env.X_CLIENT_SECRET || ''; // required for token exchange with basic auth

// Optional: where to post into community
const X_COMMUNITY_ID = process.env.X_COMMUNITY_ID || process.env.X_COMMUNITY || '';

// Cookie settings
const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || 'none'; // 'none' needed for cross-site
const COOKIE_SECURE = (process.env.COOKIE_SECURE || 'true').toLowerCase() === 'true';

// Admin
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';

// ---------- Files ----------
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const MEDIA_DB = path.join(DATA_DIR, 'media.json');

for (const dir of [DATA_DIR, UPLOADS_DIR]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
if (!fs.existsSync(MEDIA_DB)) fs.writeFileSync(MEDIA_DB, JSON.stringify({ items: [] }, null, 2));

// ---------- Middleware ----------
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));

// CORS: allow Netlify origin + localhost for dev
app.use(cors({
  origin: function (origin, cb) {
    if (!origin) return cb(null, true);
    const allowed = new Set([
      PUBLIC_SITE_URL,
      'http://localhost:8888',
      'http://localhost:3000',
      'http://127.0.0.1:8888',
      'http://127.0.0.1:3000',
    ].filter(Boolean));
    if (allowed.has(origin)) return cb(null, true);
    return cb(null, true); // be permissive; tighten later if you want
  },
  credentials: true,
}));

app.use(session({
  name: 'indian_finder_sid',
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: COOKIE_SAMESITE,
    secure: COOKIE_SECURE,
    maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
  },
}));

// Serve uploaded files
app.use('/uploads', express.static(UPLOADS_DIR, {
  setHeaders: (res) => {
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  }
}));

// ---------- Upload handling ----------
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname || '').toLowerCase() || '';
      const safeExt = ['.mp4', '.mov', '.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext) ? ext : '';
      cb(null, `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${safeExt}`);
    }
  }),
  limits: { fileSize: 220 * 1024 * 1024 }, // 220MB
});

function readMedia() {
  try {
    return JSON.parse(fs.readFileSync(MEDIA_DB, 'utf8'));
  } catch {
    return { items: [] };
  }
}
function writeMedia(db) {
  fs.writeFileSync(MEDIA_DB, JSON.stringify(db, null, 2));
}

// ---------- X OAuth helpers (OAuth2 PKCE) ----------
function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function sha256base64url(str) {
  return base64url(crypto.createHash('sha256').update(str).digest());
}

async function xFetch(url, opts = {}) {
  const res = await fetch(url, opts);
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { raw: text }; }
  if (!res.ok) {
    const err = new Error(`X API error ${res.status}`);
    err.status = res.status;
    err.body = json;
    throw err;
  }
  return json;
}

// ---------- Routes ----------
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.get('/api/x/status', (req, res) => {
  const x = req.session.x || {};
  res.json({ connected: !!x.access_token, username: x.username || null });
});

// Start OAuth flow
app.get('/api/x/connect', (req, res) => {
  if (!X_CLIENT_ID || !X_REDIRECT_URI) {
    return res.status(500).send('Missing X_CLIENT_ID or X_REDIRECT_URI');
  }

  const codeVerifier = base64url(crypto.randomBytes(32));
  const codeChallenge = sha256base64url(codeVerifier);
  const state = base64url(crypto.randomBytes(16));

  req.session.x_oauth = { codeVerifier, state, createdAt: Date.now() };

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: X_CLIENT_ID,
    redirect_uri: X_REDIRECT_URI,
    scope: [
      'tweet.read',
      'tweet.write',
      'users.read',
      'offline.access',
    ].join(' '),
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  res.redirect(`https://twitter.com/i/oauth2/authorize?${params.toString()}`);
});

// Callback: exchange code for token
app.get('/api/twitter/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) return res.status(400).send('Missing code');
    if (!state) return res.status(400).send('Missing state');

    const sess = req.session.x_oauth || {};
    if (!sess.state || state !== sess.state) return res.status(400).send('Invalid state');
    if (!sess.codeVerifier) return res.status(400).send('Missing PKCE verifier');

    // Token exchange
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: String(code),
      redirect_uri: X_REDIRECT_URI,
      code_verifier: sess.codeVerifier,
    });

    // X requires basic auth (client_id:client_secret) for confidential clients
    const basic = Buffer.from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`).toString('base64');

    const token = await xFetch('https://api.twitter.com/2/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basic}`,
      },
      body: body.toString(),
    });

    // Get user info
    const me = await xFetch('https://api.twitter.com/2/users/me', {
      headers: { 'Authorization': `Bearer ${token.access_token}` },
    });

    req.session.x = {
      access_token: token.access_token,
      refresh_token: token.refresh_token,
      expires_in: token.expires_in,
      token_type: token.token_type,
      scope: token.scope,
      user_id: me?.data?.id,
      username: me?.data?.username,
      name: me?.data?.name,
      connectedAt: Date.now(),
    };
    delete req.session.x_oauth;

    // Send back to homepage
    res.redirect(PUBLIC_SITE_URL || '/');
  } catch (e) {
    console.error('X callback error:', e.status, e.body || e);
    res.status(500).json({ ok: false, error: e.body || String(e) });
  }
});

// Refresh token if needed (best-effort)
async function ensureXAccessToken(req) {
  const x = req.session.x;
  if (!x || !x.access_token) throw new Error('Not connected to X');
  // For now, don't implement expiry tracking—just return current token.
  return x.access_token;
}

// Post a tweet (and optionally to a community)
// POST /api/x/tweet  { text, url, community_id? }
app.post('/api/x/tweet', async (req, res) => {
  try {
    const accessToken = await ensureXAccessToken(req);
    const { text, url, community_id } = req.body || {};

    const msgParts = [];
    if (text) msgParts.push(String(text).trim());
    if (url) msgParts.push(String(url).trim());
    const status = msgParts.join(' ').trim();

    if (!status) return res.status(400).json({ ok: false, error: 'Missing text/url' });

    const payload = { text: status };
    const cid = community_id || X_COMMUNITY_ID;
    if (cid) payload.community_id = String(cid);

    const out = await xFetch('https://api.twitter.com/2/tweets', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
      },
      body: JSON.stringify(payload),
    });

    res.json({ ok: true, tweet: out });
  } catch (e) {
    console.error('Tweet error:', e.status, e.body || e);
    res.status(500).json({ ok: false, error: e.body || String(e) });
  }
});

// Upload fail media
// Expects multipart/form-data with fields: title, handle (optional), file
app.options('/api/media', (req, res) => res.sendStatus(204));
app.post('/api/media', upload.single('file'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: 'No file uploaded (field name must be \"file\")' });

    const title = (req.body.title || '').toString().slice(0, 140);
    const handle = (req.body.handle || '').toString().slice(0, 64);

    const ext = path.extname(req.file.filename).toLowerCase();
    const kind = ['.mp4', '.mov'].includes(ext) ? 'video' : 'image';

    const db = readMedia();
    const id = crypto.randomBytes(8).toString('hex');
    const item = {
      id,
      title: title || 'Untitled fail',
      handle: handle || null,
      kind,
      filename: req.file.filename,
      createdAt: Date.now(),
      upvotes: 0,
    };
    db.items.unshift(item);
    writeMedia(db);

    const publicUrl = `${req.protocol}://${req.get('host')}/uploads/${encodeURIComponent(req.file.filename)}`;
    res.json({ ok: true, item: { ...item, url: publicUrl } });
  } catch (e) {
    console.error('Upload error:', e);
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Get a random item
app.get('/api/media', (req, res) => {
  const db = readMedia();
  if (!db.items.length) return res.json({ ok: true, item: null });

  const idx = Math.floor(Math.random() * db.items.length);
  const item = db.items[idx];
  const url = `${req.protocol}://${req.get('host')}/uploads/${encodeURIComponent(item.filename)}`;
  res.json({ ok: true, item: { ...item, url } });
});

// Admin: list items
app.get('/api/admin/media', (req, res) => {
  const secret = req.query.secret || req.headers['x-admin-secret'];
  if (ADMIN_SECRET && secret !== ADMIN_SECRET) return res.status(401).json({ ok: false, error: 'unauthorized' });
  res.json(readMedia());
});

app.listen(PORT, () => {
  console.log(`✅ Server listening on ${PORT}`);
  console.log('PUBLIC_SITE_URL:', PUBLIC_SITE_URL);
  console.log('X_REDIRECT_URI:', X_REDIRECT_URI);
});
