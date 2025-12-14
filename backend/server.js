// server.js — Inidan Finder backend (Railway)
// - Serves static site pages (optional, for dev)
// - Uploads MP4/JPG/PNG into /videos or /images + appends to videos.json
// - X (Twitter) OAuth 2.0 (PKCE) connect + tweet helper
//
// Env needed on Railway:
//   PUBLIC_SITE_URL=https://<your-netlify-site>.netlify.app   (or your custom domain)
//   COOKIE_SAMESITE=none
//   COOKIE_SECURE=true
//   ADMIN_SECRET=<anything>
//   X_CLIENT_ID=<from X dev portal>
//   X_CLIENT_SECRET=<from X dev portal>
//   X_REDIRECT_URI=https://<your-railway-app>.up.railway.app/api/x/callback
// Optional:
//   X_COMMUNITY_ID=1999961909404287175

try { require("dotenv").config(); } catch (e) {}

const express = require("express");
const cors = require("cors");
const session = require("express-session");
const multer = require("multer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// node-fetch v2 style (CommonJS)
let fetch;
try { fetch = require("node-fetch"); } catch (e) { fetch = global.fetch; }

const app = express();

// ✅ Railway / proxy: required for secure cookies + sessions behind reverse proxy
app.set("trust proxy", 1);

// -------------------- Env --------------------
const PORT = process.env.PORT || 3000;

const PUBLIC_SITE_URL = (process.env.PUBLIC_SITE_URL || "").trim();
const COOKIE_SAMESITE = (process.env.COOKIE_SAMESITE || "none").toLowerCase(); // 'none' for cross-site
const COOKIE_SECURE = (process.env.COOKIE_SECURE || "true").toLowerCase() === "true";

const ADMIN_SECRET = process.env.ADMIN_SECRET || "";

// X OAuth2
const X_CLIENT_ID = (process.env.X_CLIENT_ID || "").trim();
const X_CLIENT_SECRET = (process.env.X_CLIENT_SECRET || "").trim();
const X_REDIRECT_URI = (process.env.X_REDIRECT_URI || process.env.X_REDIRECT_URL || "").trim();
const X_COMMUNITY_ID = (process.env.X_COMMUNITY_ID || process.env.X_COMMUNITY || "").trim();

// -------------------- Paths --------------------
const ROOT_DIR = __dirname;
const VIDEOS_DIR = path.join(ROOT_DIR, "videos");
const IMAGES_DIR = path.join(ROOT_DIR, "images");
const VIDEOS_JSON_PATH = path.join(ROOT_DIR, "videos.json");

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}
ensureDir(VIDEOS_DIR);
ensureDir(IMAGES_DIR);

// -------------------- Middleware --------------------
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

// CORS: allow your Netlify site to call the backend with cookies (credentials)
app.use(
  cors({
    origin: function (origin, cb) {
      // allow same-origin / curl / server-to-server
      if (!origin) return cb(null, true);
      if (!PUBLIC_SITE_URL) return cb(null, true); // dev fallback
      // Allow exact match, and also allow http://localhost:* in dev
      const ok =
        origin === PUBLIC_SITE_URL ||
        origin.startsWith("http://localhost:") ||
        origin.startsWith("http://127.0.0.1:");
      return cb(ok ? null : new Error("CORS blocked"), ok);
    },
    credentials: true,
  })
);

// Sessions: stored in memory (fine for demo). Cross-site cookie requires SameSite=None + Secure=true.
app.use(
  session({
    name: "if_sid",
    secret: process.env.SESSION_SECRET || "inidan-finder-session",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: COOKIE_SAMESITE, // 'none' for cross-site
      secure: COOKIE_SECURE, // true on https
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
  })
);

// Serve static (optional) — if you also want Railway to serve pages in dev
app.use(express.static(ROOT_DIR));

// -------------------- Helpers --------------------
function readVideosJson() {
  try {
    if (!fs.existsSync(VIDEOS_JSON_PATH)) return { items: [] };
    const raw = fs.readFileSync(VIDEOS_JSON_PATH, "utf8");
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return { items: parsed };
    if (parsed && Array.isArray(parsed.items)) return parsed;
    return { items: [] };
  } catch (e) {
    return { items: [] };
  }
}
function writeVideosJson(obj) {
  fs.writeFileSync(VIDEOS_JSON_PATH, JSON.stringify(obj, null, 2));
}

function safeFilename(originalName) {
  const ext = path.extname(originalName).toLowerCase();
  const base = crypto.randomBytes(12).toString("hex");
  return `${base}${ext}`;
}

function requireAdmin(req, res, next) {
  const provided =
    (req.headers["x-admin-secret"] || "").toString() ||
    (req.query.admin_secret || "").toString() ||
    (req.body && req.body.admin_secret ? String(req.body.admin_secret) : "");
  if (!ADMIN_SECRET || provided !== ADMIN_SECRET) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }
  next();
}

// -------------------- Multer upload --------------------
const upload = multer({
  storage: multer.diskStorage({
    destination: function (req, file, cb) {
      const ext = path.extname(file.originalname).toLowerCase();
      const isVideo = [".mp4", ".mov", ".webm"].includes(ext);
      cb(null, isVideo ? VIDEOS_DIR : IMAGES_DIR);
    },
    filename: function (req, file, cb) {
      cb(null, safeFilename(file.originalname));
    },
  }),
  limits: { fileSize: 220 * 1024 * 1024 }, // ~220MB
  fileFilter: function (req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    const ok = [".mp4", ".mov", ".webm", ".jpg", ".jpeg", ".png"].includes(ext);
    cb(ok ? null : new Error("Unsupported file type"), ok);
  },
});

// -------------------- Routes --------------------
app.get("/api/status", (req, res) => {
  res.json({ ok: true, service: "inidan-finder-backend" });
});

// list media
app.get("/api/media", (req, res) => {
  const data = readVideosJson();
  res.json({ ok: true, items: data.items || [] });
});

// Upload endpoint used by submit.html
app.post("/api/upload", upload.single("file"), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: "No file" });

    const title = (req.body.title || "").toString().trim().slice(0, 120);
    const handle = (req.body.handle || "").toString().trim().slice(0, 60);

    const relPath =
      req.file.destination === VIDEOS_DIR
        ? `/videos/${req.file.filename}`
        : `/images/${req.file.filename}`;

    const type = relPath.startsWith("/videos/") ? "video" : "image";

    const data = readVideosJson();
    const item = {
      id: crypto.randomBytes(10).toString("hex"),
      type,
      title: title || (type === "video" ? "Untitled video" : "Untitled image"),
      handle: handle || "",
      src: relPath,
      createdAt: new Date().toISOString(),
      upvotes: 0,
    };
    data.items = Array.isArray(data.items) ? data.items : [];
    data.items.unshift(item);
    writeVideosJson(data);

    res.json({ ok: true, item });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "upload_failed" });
  }
});

// upvote (simple demo)
app.post("/api/upvote/:id", (req, res) => {
  const id = req.params.id;
  const data = readVideosJson();
  const items = Array.isArray(data.items) ? data.items : [];
  const idx = items.findIndex((x) => x.id === id);
  if (idx === -1) return res.status(404).json({ ok: false, error: "not_found" });
  items[idx].upvotes = (items[idx].upvotes || 0) + 1;
  writeVideosJson({ items });
  res.json({ ok: true, item: items[idx] });
});

// -------------------- X OAuth 2.0 (PKCE) --------------------
function base64url(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
function sha256(input) {
  return crypto.createHash("sha256").update(input).digest();
}

app.get("/api/x/connect", (req, res) => {
  if (!X_CLIENT_ID || !X_REDIRECT_URI) {
    return res.status(500).send("Missing X_CLIENT_ID or X_REDIRECT_URI");
  }

  const state = crypto.randomBytes(16).toString("hex");
  const codeVerifier = base64url(crypto.randomBytes(32));
  const codeChallenge = base64url(sha256(codeVerifier));

  req.session.x_oauth_state = state;
  req.session.x_code_verifier = codeVerifier;

  const scope = [
    "tweet.read",
    "users.read",
    "tweet.write",
    "offline.access",
  ].join(" ");

  const params = new URLSearchParams({
    response_type: "code",
    client_id: X_CLIENT_ID,
    redirect_uri: X_REDIRECT_URI,
    scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });

  return res.redirect(`https://twitter.com/i/oauth2/authorize?${params.toString()}`);
});

app.get("/api/x/callback", async (req, res) => {
  try {
    const { state, code, error, error_description } = req.query;

    if (error) {
      return res.status(400).send(`X OAuth error: ${error} ${error_description || ""}`);
    }
    if (!state || !code) return res.status(400).send("Missing state or code");
    if (state !== req.session.x_oauth_state) return res.status(400).send("Invalid state");

    const codeVerifier = req.session.x_code_verifier;
    if (!codeVerifier) return res.status(400).send("Missing code verifier");

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: X_CLIENT_ID,
      redirect_uri: X_REDIRECT_URI,
      code: String(code),
      code_verifier: codeVerifier,
    });

    // For confidential clients, X expects Basic Auth with client_id:client_secret
    const basic = Buffer.from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`).toString("base64");

    const tokenResp = await fetch("https://api.twitter.com/2/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basic}`,
      },
      body: body.toString(),
    });

    const tokenJson = await tokenResp.json();
    if (!tokenResp.ok) {
      return res.status(400).json({ ok: false, error: tokenJson });
    }

    req.session.x_access_token = tokenJson.access_token;
    req.session.x_refresh_token = tokenJson.refresh_token || null;
    req.session.x_connected_at = Date.now();

    // Fetch username (best-effort)
    try {
      const me = await fetch("https://api.twitter.com/2/users/me", {
        headers: { Authorization: `Bearer ${tokenJson.access_token}` },
      });
      const meJson = await me.json();
      req.session.x_username = meJson?.data?.username || null;
    } catch (_) {}

    // Redirect back to your Netlify homepage
    if (PUBLIC_SITE_URL) return res.redirect(PUBLIC_SITE_URL);
    return res.redirect("/");
  } catch (e) {
    return res.status(500).send(e.message || "callback_failed");
  }
});

app.get("/api/x/status", (req, res) => {
  res.json({
    connected: !!req.session.x_access_token,
    username: req.session.x_username || null,
  });
});

// Post a tweet (and attempt to associate with a community if supported)
app.post("/api/x/tweet", async (req, res) => {
  try {
    const token = req.session?.x_access_token;
    if (!token) return res.status(401).json({ ok: false, error: "not_connected" });

    const text = (req.body?.text || "").toString().trim();
    if (!text) return res.status(400).json({ ok: false, error: "missing_text" });

    const payload = { text };
    const communityId = (req.body?.community_id || X_COMMUNITY_ID || "").toString().trim();
    // NOTE: If X supports community posting via tweet create, it may accept a community id field.
    // If not supported for your app tier, X will return an error — we pass it only when present.
    if (communityId) payload.community_id = communityId;

    const resp = await fetch("https://api.twitter.com/2/tweets", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    const json = await resp.json();
    if (!resp.ok) return res.status(400).json({ ok: false, error: json });
    return res.json({ ok: true, data: json });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message || "tweet_failed" });
  }
});

// -------------------- Start --------------------
app.listen(PORT, () => {
  console.log(`✅ Inidan Finder backend listening on ${PORT}`);
});
