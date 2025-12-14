
/**
 * Fails.com / Indian Finder API
 * - Media vault (list, upload, upvote)
 * - X (Twitter) OAuth 2.0 PKCE connect + status
 * - Optional: share a fail to X (tweet) after connect
 *
 * Env vars (Railway):
 *   PORT=8080 (Railway sets PORT automatically)
 *   PUBLIC_SITE_URL=https://<your-netlify-site>.netlify.app   (used for redirects + share links)
 *   COOKIE_SECURE=true|false
 *   COOKIE_SAMESITE=None|Lax|Strict
 *   ADMIN_SECRET=some-long-random
 *
 *   X_CLIENT_ID=...
 *   X_CLIENT_SECRET=...
 *   X_REDIRECT_URI=https://<your-railway-app>.up.railway.app/api/x/callback
 *   X_COMMUNITY_ID=1999... (optional; API posting to communities may not be available)
 */

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const multer = require("multer");

const app = express();

// -------------------- Config --------------------
const PORT = process.env.PORT || 8080;
const PUBLIC_SITE_URL = (process.env.PUBLIC_SITE_URL || "").replace(/\/+$/, ""); // no trailing slash

const COOKIE_SECURE = String(process.env.COOKIE_SECURE || "true").toLowerCase() === "true";
const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || "None"; // "None" for cross-site cookies (Netlify -> Railway)
const ADMIN_SECRET = process.env.ADMIN_SECRET || "dev_admin_secret_change_me";

const X_CLIENT_ID = process.env.X_CLIENT_ID || process.env.TWITTER_CLIENT_ID;
const X_CLIENT_SECRET = process.env.X_CLIENT_SECRET || process.env.TWITTER_CLIENT_SECRET;
const X_REDIRECT_URI = process.env.X_REDIRECT_URI || process.env.TWITTER_CALLBACK_URL || process.env.TWITTER_REDIRECT_URL;
const X_COMMUNITY_ID = process.env.X_COMMUNITY_ID || ""; // optional

// -------------------- Middleware --------------------
app.set("trust proxy", 1);

app.use(cors({
  origin: function (origin, cb) {
    // allow same-origin, Netlify preview, and localhost
    if (!origin) return cb(null, true);
    if (origin.includes("netlify.app") || origin.includes("localhost") || origin.includes("127.0.0.1")) return cb(null, true);
    // also allow your public site URL if set
    if (PUBLIC_SITE_URL && origin === PUBLIC_SITE_URL) return cb(null, true);
    return cb(null, true); // loosen to avoid headaches (you can tighten later)
  },
  credentials: true
}));

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  name: "fails_sid",
  secret: process.env.SESSION_SECRET || ADMIN_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: COOKIE_SAMESITE,
    maxAge: 1000 * 60 * 60 * 24 * 14 // 14 days
  }
}));

// -------------------- Storage (media) --------------------
const DATA_DIR = path.join(__dirname, "data");
const UPLOADS_DIR = path.join(__dirname, "uploads");
const MEDIA_JSON_PATH = path.join(DATA_DIR, "media.json");

function ensureDirs() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  if (!fs.existsSync(MEDIA_JSON_PATH)) fs.writeFileSync(MEDIA_JSON_PATH, JSON.stringify([], null, 2));
}
ensureDirs();

function readMedia() {
  try {
    const raw = fs.readFileSync(MEDIA_JSON_PATH, "utf8");
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

function writeMedia(arr) {
  fs.writeFileSync(MEDIA_JSON_PATH, JSON.stringify(arr, null, 2));
}

function safeExt(filename) {
  const ext = path.extname(filename || "").toLowerCase();
  const allowed = new Set([".mp4", ".mov", ".webm", ".jpg", ".jpeg", ".png", ".gif"]);
  return allowed.has(ext) ? ext : "";
}

function isImageExt(ext) {
  return [".jpg", ".jpeg", ".png", ".gif"].includes(ext);
}

// Serve uploaded files
app.use("/uploads", express.static(UPLOADS_DIR, {
  setHeaders: (res) => {
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
  }
}));

// Multer upload config
const upload = multer({
  storage: multer.diskStorage({
    destination: function (_req, _file, cb) {
      cb(null, UPLOADS_DIR);
    },
    filename: function (_req, file, cb) {
      const ext = safeExt(file.originalname);
      const base = crypto.randomBytes(16).toString("hex");
      cb(null, `${base}${ext}`);
    }
  }),
  limits: { fileSize: 220 * 1024 * 1024 } // ~220MB
});

// -------------------- Helper: PKCE --------------------
function base64URLEncode(buffer) {
  return buffer.toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest();
}

function createCodeVerifier() {
  return base64URLEncode(crypto.randomBytes(32));
}

function createCodeChallenge(verifier) {
  return base64URLEncode(sha256(verifier));
}

// -------------------- Health --------------------
app.get("/api/health", (_req, res) => res.json({ ok: true }));

// -------------------- Media API --------------------
app.get("/api/media", (_req, res) => {
  const media = readMedia();
  res.json(media);
});

app.post("/api/media/:id/upvote", (req, res) => {
  const id = req.params.id;
  const media = readMedia();
  const idx = media.findIndex(m => String(m.id) === String(id));
  if (idx === -1) return res.status(404).json({ ok: false, error: "Not found" });

  media[idx].votes = (media[idx].votes || 0) + 1;
  writeMedia(media);
  return res.json({ ok: true, votes: media[idx].votes });
});

// Upload a new fail (video or image)
app.post("/api/upload", upload.single("file"), (req, res) => {
  try {
    const title = (req.body.title || "").trim().slice(0, 140);
    const author = (req.body.author || "").trim().slice(0, 80);

    if (!req.file) return res.status(400).json({ ok: false, error: "No file uploaded" });

    const ext = safeExt(req.file.originalname);
    if (!ext) return res.status(400).json({ ok: false, error: "Unsupported file type" });

    const item = {
      id: crypto.randomBytes(10).toString("hex"),
      title: title || "Fail",
      author: author || "",
      src: `/uploads/${req.file.filename}`,
      mediaType: isImageExt(ext) ? "image" : "video",
      votes: 0,
      createdAt: new Date().toISOString()
    };

    const media = readMedia();
    media.unshift(item);
    writeMedia(media);

    return res.json({ ok: true, item });
  } catch (err) {
    console.error("Upload error:", err);
    return res.status(500).json({ ok: false, error: "Upload failed" });
  }
});

// -------------------- X Connect (OAuth 2.0) --------------------
app.get("/api/x/status", (req, res) => {
  const username = req.session.x_username || null;
  res.json({ connected: !!username, username });
});

app.get("/api/x/connect", async (req, res) => {
  try {
    if (!X_CLIENT_ID || !X_CLIENT_SECRET || !X_REDIRECT_URI) {
      return res.status(500).send("X OAuth env vars missing (X_CLIENT_ID / X_CLIENT_SECRET / X_REDIRECT_URI).");
    }

    const state = base64URLEncode(crypto.randomBytes(16));
    const codeVerifier = createCodeVerifier();
    const codeChallenge = createCodeChallenge(codeVerifier);

    req.session.x_oauth_state = state;
    req.session.x_code_verifier = codeVerifier;

    req.session.save(() => {
      const params = new URLSearchParams({
        response_type: "code",
        client_id: X_CLIENT_ID,
        redirect_uri: X_REDIRECT_URI,
        scope: "tweet.read users.read tweet.write offline.access",
        state,
        code_challenge: codeChallenge,
        code_challenge_method: "S256"
      });

      // Note: twitter.com/i/oauth2/authorize redirects to x.com in browser (normal)
      return res.redirect(`https://twitter.com/i/oauth2/authorize?${params.toString()}`);
    });
  } catch (err) {
    console.error("Connect error:", err);
    return res.status(500).send("X connect failed");
  }
});

app.get("/api/x/callback", async (req, res) => {
  try {
    const { state, code } = req.query;

    if (!state || !code) return res.status(400).send("Missing code/state");
    if (!req.session.x_oauth_state || state !== req.session.x_oauth_state) {
      return res.status(400).send("Invalid state");
    }

    const codeVerifier = req.session.x_code_verifier;
    if (!codeVerifier) return res.status(400).send("Missing code verifier");

    // Exchange code -> token
    const tokenRes = await fetch("https://api.twitter.com/2/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic " + Buffer.from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`).toString("base64")
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: String(code),
        redirect_uri: X_REDIRECT_URI,
        code_verifier: codeVerifier
      })
    });

    const tokenJson = await tokenRes.json();
    if (!tokenRes.ok) {
      console.error("Token exchange failed:", tokenJson);
      return res.status(400).json({ ok: false, error: tokenJson });
    }

    const accessToken = tokenJson.access_token;
    req.session.x_access_token = accessToken;
    req.session.x_refresh_token = tokenJson.refresh_token || null;

    // Fetch the user
    const meRes = await fetch("https://api.twitter.com/2/users/me?user.fields=username", {
      headers: { "Authorization": `Bearer ${accessToken}` }
    });
    const meJson = await meRes.json();
    if (!meRes.ok) {
      console.error("User lookup failed:", meJson);
      return res.status(400).json({ ok: false, error: meJson });
    }

    req.session.x_user_id = meJson?.data?.id || null;
    req.session.x_username = meJson?.data?.username || null;

    // Clean transient oauth fields
    req.session.x_oauth_state = null;
    req.session.x_code_verifier = null;

    const redirectTo = PUBLIC_SITE_URL ? `${PUBLIC_SITE_URL}/` : "/";
    return req.session.save(() => res.redirect(redirectTo));
  } catch (err) {
    console.error("Callback error:", err);
    return res.status(500).send("X callback failed");
  }
});

app.post("/api/x/disconnect", (req, res) => {
  req.session.x_access_token = null;
  req.session.x_refresh_token = null;
  req.session.x_username = null;
  req.session.x_user_id = null;
  req.session.x_oauth_state = null;
  req.session.x_code_verifier = null;
  return req.session.save(() => res.json({ ok: true }));
});

// -------------------- Share a fail to X --------------------
// Body: { url: "https://fails.com/fail/<id>", text?: "...", communityId?: "..." }
app.post("/api/x/share-fail", async (req, res) => {
  try {
    const token = req.session.x_access_token;
    if (!token) return res.status(401).json({ ok: false, error: "Not connected to X" });

    const url = String(req.body.url || "").trim();
    if (!url) return res.status(400).json({ ok: false, error: "Missing url" });

    const username = req.session.x_username || "someone";
    const text =
      String(req.body.text || "").trim() ||
      `I just found a fail! Check it out here ${url}`;

    // Post tweet
    const tweetRes = await fetch("https://api.twitter.com/2/tweets", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify({ text })
    });

    const tweetJson = await tweetRes.json();
    if (!tweetRes.ok) {
      console.error("Tweet failed:", tweetJson);
      return res.status(400).json({ ok: false, error: tweetJson });
    }

    // NOTE: As of now, X's public API for posting directly into Communities isn't consistently available.
    // If you discover an endpoint for it later, we can wire it in here using X_COMMUNITY_ID.

    return res.json({ ok: true, tweet: tweetJson, connectedAs: username, communityId: req.body.communityId || X_COMMUNITY_ID || null });
  } catch (err) {
    console.error("Share-fail error:", err);
    return res.status(500).json({ ok: false, error: "Share failed" });
  }
});

// -------------------- Start --------------------
app.listen(PORT, () => {
  console.log(`Fails API running on port ${PORT}`);
  console.log(`Uploads dir: ${UPLOADS_DIR}`);
});
