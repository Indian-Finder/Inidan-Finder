import express from "express";
import session from "express-session";
import cors from "cors";
import multer from "multer";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

/* =====================
   SETUP
===================== */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set("trust proxy", 1); // ✅ Railway + secure cookies

/* =====================
   ENV
===================== */
const PORT = process.env.PORT || 8080;

const ADMIN_SECRET = process.env.ADMIN_SECRET || "dev_admin_change_me";
const PUBLIC_SITE_URL = process.env.PUBLIC_SITE_URL || "http://localhost:5173";

const COOKIE_SECURE = process.env.COOKIE_SECURE === "true";
const COOKIE_SAMESITE = (process.env.COOKIE_SAMESITE || "lax").toLowerCase();

const DEBUG_AUTH = (process.env.DEBUG_AUTH || "true") === "true";
const SESSION_SECRET =
  process.env.SESSION_SECRET || "fails_session_secret_change_me";

// X OAuth
const X_CLIENT_ID = process.env.X_CLIENT_ID || "";
const X_CLIENT_SECRET = process.env.X_CLIENT_SECRET || "";
const X_REDIRECT_URI = process.env.X_REDIRECT_URI || "";
const X_SCOPES = (process.env.X_SCOPES ||
  "tweet.read tweet.write users.read offline.access").trim();

/* =====================
   HELPERS
===================== */
function dlog(...args) {
  if (DEBUG_AUTH) console.log("[DEBUG]", ...args);
}
function mustEnv(val, name) {
  if (!val) throw new Error(`Missing env var: ${name}`);
  return val;
}
function base64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}
function sha256(input) {
  return crypto.createHash("sha256").update(input).digest();
}

/* =====================
   MIDDLEWARE
===================== */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  cors({
    origin: PUBLIC_SITE_URL,
    credentials: true,
  })
);

app.use(
  session({
    name: "fails.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE, // "none" for cross-site cookies
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

/* =====================
   STORAGE
===================== */
const uploadsDir = path.join(__dirname, "uploads");
const dataDir = path.join(__dirname, "data");
const videosFile = path.join(dataDir, "videos.json");

if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(videosFile)) fs.writeFileSync(videosFile, "[]");

const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname || "");
    cb(null, `${Date.now()}-${crypto.randomUUID()}${ext}`);
  },
});
const upload = multer({ storage });

function readVideos() {
  return JSON.parse(fs.readFileSync(videosFile, "utf8"));
}
function writeVideos(videos) {
  fs.writeFileSync(videosFile, JSON.stringify(videos, null, 2));
}

/* =====================
   AUTH
===================== */
function requireAdmin(req, res, next) {
  if (req.session?.isAdmin) return next();
  return res.status(401).json({ ok: false, error: "Unauthorized" });
}

/* =====================
   HEALTH + DEBUG
===================== */
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    version: "fails-server-v1",
    port: String(PORT),
    cookie: { secure: COOKIE_SECURE, sameSite: COOKIE_SAMESITE },
    publicSiteUrl: PUBLIC_SITE_URL,
    xConfigured: !!(X_CLIENT_ID && X_CLIENT_SECRET && X_REDIRECT_URI),
  });
});

app.get("/api/debug/session", (req, res) => {
  res.json({
    ok: true,
    origin: req.headers.origin || null,
    cookieHeaderPresent: !!req.headers.cookie,
    sessionID: req.sessionID,
    isAdmin: !!req.session?.isAdmin,
    xConnected: !!req.session?.x?.access_token,
  });
});

/* =====================
   ADMIN (SESSION)
===================== */
app.post("/api/admin/login", (req, res) => {
  const password = String(req.body.password || "");
  if (password !== ADMIN_SECRET) {
    return res.status(401).json({ ok: false, error: "Invalid password" });
  }
  req.session.isAdmin = true;
  req.session.save((err) => {
    if (err) return res.status(500).json({ ok: false, error: "Session save failed" });
    res.json({ ok: true });
  });
});

app.post("/api/admin/logout", (req, res) => {
  req.session.isAdmin = false;
  req.session.save(() => res.json({ ok: true }));
});

app.get("/api/admin/status", (req, res) => {
  res.json({ ok: true, isAdmin: !!req.session?.isAdmin });
});

app.get("/api/admin/fails", requireAdmin, (req, res) => {
  res.json(readVideos());
});

app.delete("/api/admin/fails/:id", requireAdmin, (req, res) => {
  const id = req.params.id;
  const videos = readVideos();
  const idx = videos.findIndex((v) => v.id === id);
  if (idx === -1) return res.status(404).json({ ok: false, error: "Not found" });

  const [removed] = videos.splice(idx, 1);
  writeVideos(videos);

  try {
    const fullPath = path.join(uploadsDir, removed.filename);
    if (removed.filename && fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
  } catch {}

  res.json({ ok: true });
});

/* =====================
   UPLOAD
===================== */
app.post("/api/upload", upload.any(), (req, res) => {
  const file = req.files?.[0];
  if (!file) return res.status(400).json({ ok: false, error: "No file uploaded" });

  const videos = readVideos();

  const fail = {
    id: crypto.randomUUID(),
    filename: file.filename,
    url: `/uploads/${file.filename}`, // ✅ frontend expects url
    title: req.body.title || "",
    author: req.body.author || "",
    createdAt: Date.now(),
    votes: 0,
  };

  videos.unshift(fail);
  writeVideos(videos);

  res.json({ ok: true, fail });
});

/* =====================
   FAILS API (NEW)
===================== */
app.get("/api/fails", (_req, res) => {
  res.json(readVideos());
});

app.get("/api/fails/:id", (req, res) => {
  const fail = readVideos().find((v) => v.id === req.params.id);
  if (!fail) return res.status(404).json({ ok: false, error: "Not found" });
  res.json(fail);
});

app.post("/api/fails/:id/upvote", (req, res) => {
  const id = req.params.id;
  const videos = readVideos();
  const fail = videos.find((v) => v.id === id);
  if (!fail) return res.status(404).json({ ok: false, error: "Not found" });

  fail.votes = (fail.votes || 0) + 1;
  writeVideos(videos);
  res.json({ ok: true, votes: fail.votes });
});

/* =====================
   BACK-COMPAT (OLD) /api/media
   - Your old index expected {id, src, mediaType, votes}
===================== */
function inferMediaTypeFromUrl(u) {
  const url = (u || "").toLowerCase();
  if (url.match(/\.(png|jpg|jpeg|webp|gif)(\?|$)/)) return "image";
  return "video";
}

app.get("/api/media", (_req, res) => {
  const videos = readVideos();
  const out = videos.map((v) => ({
    id: v.id,
    title: v.title || "Fail",
    author: v.author || "",
    src: v.url || v.src,
    mediaType: v.mediaType || inferMediaTypeFromUrl(v.url || v.src),
    votes: v.votes || 0,
  }));
  res.json(out);
});

app.post("/api/media/:id/upvote", (req, res) => {
  // alias to new upvote
  req.url = `/api/fails/${req.params.id}/upvote`;
  return app._router.handle(req, res, () => {});
});

/* =====================
   X (Twitter) OAuth 2.0 PKCE
===================== */
app.get("/api/x/status", (req, res) => {
  res.json({
    ok: true,
    connected: !!req.session?.x?.access_token,
    has_refresh: !!req.session?.x?.refresh_token,
    scope: req.session?.x?.scope || null,
  });
});

app.post("/api/x/disconnect", (req, res) => {
  req.session.x = null;
  res.json({ ok: true });
});

app.get("/api/x/connect", (req, res) => {
  try {
    mustEnv(X_CLIENT_ID, "X_CLIENT_ID");
    mustEnv(X_REDIRECT_URI, "X_REDIRECT_URI");
  } catch (e) {
    return res.status(500).send(String(e.message || e));
  }

  const code_verifier = base64url(crypto.randomBytes(32));
  const code_challenge = base64url(sha256(code_verifier));
  const state = base64url(crypto.randomBytes(16));

  req.session.x_oauth = { code_verifier, state, createdAt: Date.now() };

  const authUrl = new URL("https://twitter.com/i/oauth2/authorize");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", X_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", X_REDIRECT_URI);
  authUrl.searchParams.set("scope", X_SCOPES);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", code_challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  return res.redirect(authUrl.toString());
});

// ✅ Back-compat for old callback path
app.get("/api/twitter/callback", (req, res) => {
  const qs = new URLSearchParams(req.query).toString();
  res.redirect(`/api/x/callback?${qs}`);
});

app.get("/api/x/callback", async (req, res) => {
  try {
    mustEnv(X_CLIENT_ID, "X_CLIENT_ID");
    mustEnv(X_CLIENT_SECRET, "X_CLIENT_SECRET");
    mustEnv(X_REDIRECT_URI, "X_REDIRECT_URI");
  } catch (e) {
    return res.status(500).send(String(e.message || e));
  }

  const { code, state, error, error_description } = req.query;

  if (error) {
    return res
      .status(400)
      .send(`X OAuth error: ${error} ${error_description || ""}`);
  }
  if (!code || !state) return res.status(400).send("Missing code/state");

  const stored = req.session?.x_oauth;
  if (!stored?.code_verifier || !stored?.state) {
    return res.status(400).send("Missing stored PKCE state (session lost)");
  }
  if (stored.state !== state) {
    return res.status(400).send("State mismatch");
  }

  const tokenUrl = "https://api.twitter.com/2/oauth2/token";
  const basic = Buffer.from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`).toString("base64");

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: String(code),
    redirect_uri: X_REDIRECT_URI,
    code_verifier: stored.code_verifier,
  });

  const tokenRes = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });

  const tokenJson = await tokenRes.json();
  if (!tokenRes.ok) {
    console.error("X token exchange failed:", tokenJson);
    return res.status(500).send("Token exchange failed. Check server logs.");
  }

  req.session.x = {
    access_token: tokenJson.access_token,
    refresh_token: tokenJson.refresh_token,
    expires_in: tokenJson.expires_in,
    scope: tokenJson.scope,
    token_type: tokenJson.token_type,
    createdAt: Date.now(),
  };

  req.session.x_oauth = null;

  // back to site
  return res.redirect(`${PUBLIC_SITE_URL}/index.html?x=connected`);
});

app.post("/api/x/tweet", async (req, res) => {
  const access_token = req.session?.x?.access_token;
  if (!access_token) {
    return res.status(401).json({ ok: false, error: "Not connected to X" });
  }

  const text = String(req.body?.text || "").trim();
  if (!text) return res.status(400).json({ ok: false, error: "Missing text" });

  const tweetRes = await fetch("https://api.twitter.com/2/tweets", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${access_token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ text }),
  });

  const json = await tweetRes.json();
  if (!tweetRes.ok) {
    console.error("Tweet failed:", json);
    return res.status(500).json({ ok: false, error: "Tweet failed", details: json });
  }

  res.json({ ok: true, tweet: json });
});

/* =====================
   STATIC UPLOADS
===================== */
app.use("/uploads", express.static(uploadsDir));

/* =====================
   ERROR HANDLER
===================== */
app.use((err, req, res, next) => {
  if (err?.name === "MulterError") {
    console.error("MULTER ERROR:", err);
    return res.status(400).json({ ok: false, error: err.message });
  }
  console.error("SERVER ERROR:", err);
  res.status(500).json({ ok: false, error: "Server error" });
});

/* =====================
   START
===================== */
app.listen(PORT, () => {
  console.log(`🔥 fails backend running on ${PORT}`);
  console.log(`[CFG] PUBLIC_SITE_URL=${PUBLIC_SITE_URL}`);
  console.log(`[CFG] COOKIE_SECURE=${COOKIE_SECURE} COOKIE_SAMESITE=${COOKIE_SAMESITE}`);
  console.log(
    `[CFG] X configured=${!!(X_CLIENT_ID && X_CLIENT_SECRET && X_REDIRECT_URI)} redirect="${X_REDIRECT_URI}"`
  );
});




