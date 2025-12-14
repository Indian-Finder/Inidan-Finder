// server.js - Indian Finder backend (Railway)
// Uploads + X OAuth2 + Tweet-to-community helper
// Node/Express (CommonJS)

const express = require('express');
const cors = require('cors');
const session = require('express-session');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------- Env ----------
const PORT = process.env.PORT || 3000;

// Public site origin (Netlify) so cookies can work cross-site
const PUBLIC_SITE_URL = (process.env.PUBLIC_SITE_URL || '').replace(/\/+$/, '');

// X OAuth2 (confidential client)
const X_REDIRECT_URI = process.env.X_REDIRECT_URI || process.env.X_REDIRECT_URL || '';
const X_CLIENT_ID = process.env.X_CLIENT_ID || '';
const X_CLIENT_SECRET = process.env.X_CLIENT_SECRET || ''; // required for token exchange w/ basic auth
const X_COMMUNITY_ID = process.env.X_COMMUNITY_ID || process.env.X_COMMUNITY || ''; // optional default

// Cookie / session
const COOKIE_SAMESITE = (process.env.COOKIE_SAMESITE || 'none').toLowerCase(); // 'none' for cross-site
const COOKIE_SECURE = String(process.env.COOKIE_SECURE ?? 'true').toLowerCase() === 'true';
const SESSION_SECRET = process.env.SESSION_SECRET || process.env.ADMIN_SECRET || 'dev_secret_change_me';

// Upload settings
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 220); // keep a little buffer over 200MB
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const MEDIA_DB_PATH = path.join(DATA_DIR, 'media.json'); // our writable DB

// ---------- Helpers ----------
function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function readJsonSafe(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw.trim()) return fallback;
    return JSON.parse(raw);
  } catch (e) {
    return fallback;
  }
}

function writeJsonAtomic(filePath, obj) {
  const tmp = filePath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), 'utf8');
  fs.renameSync(tmp, filePath);
}

function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function randomId(n = 12) {
  return crypto.randomBytes(n).toString('hex');
}

function absoluteUrl(req, p) {
  // Build absolute URL for returned media links
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const host = req.headers['x-forwarded-host'] || req.get('host');
  return `${proto}://${host}${p.startsWith('/') ? p : '/' + p}`;
}

// ---------- App ----------
ensureDir(DATA_DIR);
ensureDir(UPLOAD_DIR);

const app = express();

// Railway/Proxies: needed for secure cookies + correct protocol
app.set('trust proxy', 1);

// CORS for Netlify frontend
const allowedOrigins = new Set(
  [PUBLIC_SITE_URL].filter(Boolean)
);

app.use(cors({
  origin: function (origin, cb) {
    // allow same-origin, curl, etc.
    if (!origin) return cb(null, true);
    if (allowedOrigins.size === 0) return cb(null, true);
    return cb(null, allowedOrigins.has(origin));
  },
  credentials: true,
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  name: 'if_session',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: COOKIE_SAMESITE, // 'none'
    secure: COOKIE_SECURE,     // true on https
    maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
  },
}));

// Serve uploaded files
app.use('/uploads', express.static(UPLOAD_DIR, {
  setHeaders: (res) => {
    // allow embedding/preview
    res.setHeader('Access-Control-Allow-Origin', PUBLIC_SITE_URL || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
}));

// Basic health
app.get('/api/status', (req, res) => res.json({ ok: true }));

// ---------- Media DB ----------
// Seed from legacy files if present (videos.json) and our media.json
function loadMedia() {
  const ours = readJsonSafe(MEDIA_DB_PATH, []);
  // Optional legacy: /videos.json at repo root
  const legacyPath = path.join(__dirname, 'videos.json');
  const legacy = readJsonSafe(legacyPath, []);
  const merged = [...legacy, ...ours];

  // de-dupe by id/url
  const seen = new Set();
  const out = [];
  for (const item of merged) {
    const key = item.id || item.url || JSON.stringify(item);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

function saveMedia(newItems) {
  // We only write to our writable DB to avoid editing repo-root files
  writeJsonAtomic(MEDIA_DB_PATH, newItems);
}

// Return a random fail (video or image)
app.get('/api/media', (req, res) => {
  const list = loadMedia();
  if (!list.length) return res.status(404).json({ ok: false, error: 'no_media' });

  const pick = list[Math.floor(Math.random() * list.length)];
  res.json({ ok: true, media: pick });
});

// ---------- Uploads ----------
const storage = multer.diskStorage({
  destination: function (_req, _file, cb) {
    cb(null, UPLOAD_DIR);
  },
  filename: function (_req, file, cb) {
    const ext = path.extname(file.originalname || '').slice(0, 10) || '';
    cb(null, `${Date.now()}_${randomId(8)}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_UPLOAD_MB * 1024 * 1024,
  }
});

// Expects multipart/form-data:
// - file (video/mp4 or image/png|jpg|jpeg)
// - title (optional)
// - handle (optional)
// - shareToX ("true"/"false") optional
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: 'missing_file' });

    const mime = (req.file.mimetype || '').toLowerCase();
    const isVideo = mime.includes('video');
    const isImage = mime.includes('image');
    if (!isVideo && !isImage) {
      // remove file if unsupported
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ ok: false, error: 'unsupported_type', mime });
    }

    const title = String(req.body.title || req.body.name || '').trim();
    const handle = String(req.body.handle || req.body.username || '').trim();

    const urlPath = `/uploads/${encodeURIComponent(path.basename(req.file.path))}`;
    const publicUrl = absoluteUrl(req, urlPath);

    const item = {
      id: randomId(10),
      type: isVideo ? 'video' : 'image',
      title: title || (isVideo ? 'Untitled video' : 'Untitled image'),
      handle: handle || '',
      url: publicUrl,
      createdAt: new Date().toISOString(),
      votes: 0,
    };

    // append to our DB
    const current = readJsonSafe(MEDIA_DB_PATH, []);
    current.unshift(item); // newest first
    saveMedia(current);

    // Optional: auto-post to X community
    const shareToX = String(req.body.shareToX || '').toLowerCase() === 'true';
    let xPosted = false;
    let xError = null;

    if (shareToX) {
      if (!req.session?.x?.access_token) {
        xError = 'x_not_connected';
      } else {
        try {
          const communityId = String(req.body.communityId || X_COMMUNITY_ID || '').trim();
          const tweetText = `I just found a fail! Check it out here ${publicUrl}`;
          await postTweetToXCommunity({
            accessToken: req.session.x.access_token,
            text: tweetText,
            communityId: communityId || null,
          });
          xPosted = true;
        } catch (e) {
          xError = e?.message || String(e);
        }
      }
    }

    res.json({ ok: true, media: item, xPosted, xError });
  } catch (err) {
    const msg = err?.message || String(err);
    // Multer file size error
    if (msg.toLowerCase().includes('file too large')) {
      return res.status(413).json({ ok: false, error: 'file_too_large' });
    }
    return res.status(500).json({ ok: false, error: 'upload_failed', details: msg });
  }
});

// ---------- X OAuth2 (Authorization Code + PKCE) ----------
function getBase64Url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function makeCodeVerifier() {
  return getBase64Url(crypto.randomBytes(32));
}

function makeCodeChallenge(verifier) {
  return getBase64Url(crypto.createHash('sha256').update(verifier).digest());
}

function requireXEnv(req, res) {
  if (!X_CLIENT_ID || !X_REDIRECT_URI) {
    res.status(500).json({ ok: false, error: 'missing_x_env', need: ['X_CLIENT_ID', 'X_REDIRECT_URI'] });
    return false;
  }
  // Client secret is required for confidential client token exchange (basic auth)
  if (!X_CLIENT_SECRET) {
    res.status(500).json({ ok: false, error: 'missing_x_client_secret', need: ['X_CLIENT_SECRET'] });
    return false;
  }
  return true;
}

app.get('/api/x/connect', (req, res) => {
  if (!requireXEnv(req, res)) return;

  const codeVerifier = makeCodeVerifier();
  const codeChallenge = makeCodeChallenge(codeVerifier);
  const state = randomId(16);

  req.session.x_oauth = { codeVerifier, state, createdAt: Date.now() };

  const scope = encodeURIComponent('tweet.read users.read offline.access tweet.write');
  const redirectUri = encodeURIComponent(X_REDIRECT_URI);

  const authUrl =
    `https://twitter.com/i/oauth2/authorize?response_type=code` +
    `&client_id=${encodeURIComponent(X_CLIENT_ID)}` +
    `&redirect_uri=${redirectUri}` +
    `&scope=${scope}` +
    `&state=${encodeURIComponent(state)}` +
    `&code_challenge=${encodeURIComponent(codeChallenge)}` +
    `&code_challenge_method=S256`;

  res.redirect(authUrl);
});

app.get('/api/x/callback', async (req, res) => {
  try {
    if (!requireXEnv(req, res)) return;

    const { code, state, error, error_description } = req.query;

    if (error) {
      return res.status(400).send(`X auth error: ${error} ${error_description || ''}`);
    }

    const saved = req.session.x_oauth;
    if (!saved || !saved.state || state !== saved.state) {
      return res.status(400).send('Invalid state');
    }
    if (!code) return res.status(400).send('Missing code');

    // Exchange code for token (confidential client uses Basic auth)
    const basic = Buffer.from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`).toString('base64');

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: String(code),
      redirect_uri: X_REDIRECT_URI,
      code_verifier: saved.codeVerifier,
    }).toString();

    const tokenResp = await fetch('https://api.twitter.com/2/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basic}`,
      },
      body,
    });

    const tokenJson = await tokenResp.json();
    if (!tokenResp.ok) {
      return res.status(400).send(JSON.stringify(tokenJson));
    }

    // Store tokens in session
    req.session.x = {
      access_token: tokenJson.access_token,
      refresh_token: tokenJson.refresh_token,
      scope: tokenJson.scope,
      token_type: tokenJson.token_type,
      expires_in: tokenJson.expires_in,
      obtained_at: Date.now(),
    };

    // Fetch username for status endpoint
    const me = await fetch('https://api.twitter.com/2/users/me?user.fields=username', {
      headers: { 'Authorization': `Bearer ${tokenJson.access_token}` }
    });
    const meJson = await me.json();
    if (me.ok && meJson?.data?.username) {
      req.session.x.username = meJson.data.username;
    }

    // Back to site home (or specified)
    const go = PUBLIC_SITE_URL || '/';
    res.redirect(go);
  } catch (e) {
    res.status(500).send(`Callback error: ${e?.message || String(e)}`);
  }
});

app.get('/api/x/status', (req, res) => {
  const connected = Boolean(req.session?.x?.access_token);
  res.json({ connected, username: req.session?.x?.username || null });
});

app.post('/api/x/logout', (req, res) => {
  req.session.x = null;
  req.session.x_oauth = null;
  res.json({ ok: true });
});

// Post tweet to X community (server-side helper)
async function postTweetToXCommunity({ accessToken, text, communityId }) {
  // Docs: POST /2/tweets supports "community_id" to post into a community (if permitted)
  // https://developer.x.com/en/docs/x-api/tweets/manage-tweets/api-reference/post-tweets
  const payload = { text };
  if (communityId) payload.community_id = String(communityId);

  const resp = await fetch('https://api.twitter.com/2/tweets', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
    },
    body: JSON.stringify(payload),
  });

  const json = await resp.json();
  if (!resp.ok) {
    const msg = json?.detail || json?.title || json?.error_description || JSON.stringify(json);
    throw new Error(`X tweet failed: ${msg}`);
  }
  return json;
}

// Optional explicit endpoint (instead of auto-post during upload)
app.post('/api/x/tweet', async (req, res) => {
  try {
    if (!req.session?.x?.access_token) return res.status(401).json({ ok: false, error: 'x_not_connected' });
    const text = String(req.body.text || '').trim();
    if (!text) return res.status(400).json({ ok: false, error: 'missing_text' });

    const communityId = String(req.body.communityId || X_COMMUNITY_ID || '').trim();
    const out = await postTweetToXCommunity({
      accessToken: req.session.x.access_token,
      text,
      communityId: communityId || null,
    });

    res.json({ ok: true, result: out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

// ---------- Root ----------
app.get('/', (_req, res) => {
  res.send('Indian Finder backend is running.');
});

app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
  console.log(`PUBLIC_SITE_URL=${PUBLIC_SITE_URL || '(none)'}`);
  console.log(`Uploads dir: ${UPLOAD_DIR}`);
});
