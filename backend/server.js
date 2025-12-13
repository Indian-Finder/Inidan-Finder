try { require("dotenv").config(); } catch (e) {}

const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const fetch = require("node-fetch");

const app = express();
const PORT = process.env.PORT || 8080;

// -------------------- Config --------------------
const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  process.env.PUBLIC_SITE_URL ||
  ""; // optional (recommended if frontend is on a different domain)

const COOKIE_SECURE = String(process.env.COOKIE_SECURE || "true") === "true";
const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || "none";

// Accept either X_* or TWITTER_* env var names
const X_CLIENT_ID = process.env.X_CLIENT_ID || process.env.TWITTER_CLIENT_ID;
const X_CLIENT_SECRET =
  process.env.X_CLIENT_SECRET || process.env.TWITTER_CLIENT_SECRET;

// Prefer X_REDIRECT_URI; fall back to TWITTER_CALLBACK_URL
const X_REDIRECT_URI =
  process.env.X_REDIRECT_URI || process.env.TWITTER_CALLBACK_URL;

// Where to send the user after a successful OAuth callback
const TWITTER_SUCCESS_REDIRECT =
  process.env.TWITTER_SUCCESS_REDIRECT ||
  FRONTEND_ORIGIN ||
  "/";

// -------------------- Middleware --------------------
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

app.use(
  session({
    name: "fails.sid",
    secret: process.env.ADMIN_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE,
      maxAge: 30 * 24 * 60 * 60 * 1000,
    },
  })
);

// Enable CORS with credentials if you have a separate frontend origin
if (FRONTEND_ORIGIN) {
  const cors = require("cors");
  app.use(
    cors({
      origin: FRONTEND_ORIGIN,
      credentials: true,
    })
  );
}

// -------------------- Helpers --------------------
function base64url(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function sha256Base64Url(str) {
  return base64url(crypto.createHash("sha256").update(str).digest());
}

function requireXConfig() {
  if (!X_CLIENT_ID || !X_CLIENT_SECRET || !X_REDIRECT_URI) {
    const missing = [];
    if (!X_CLIENT_ID) missing.push("X_CLIENT_ID (or TWITTER_CLIENT_ID)");
    if (!X_CLIENT_SECRET) missing.push("X_CLIENT_SECRET (or TWITTER_CLIENT_SECRET)");
    if (!X_REDIRECT_URI) missing.push("X_REDIRECT_URI (or TWITTER_CALLBACK_URL)");
    const err = new Error("Missing: " + missing.join(", "));
    err.status = 500;
    throw err;
  }
}

async function ensureXToken(req) {
  const token = req.session?.x_access_token;
  if (!token) {
    const err = new Error("Not logged in to X/Twitter. Hit /api/x/connect first.");
    err.status = 401;
    throw err;
  }
  return token;
}

// -------------------- Health --------------------
app.get("/api/status", (req, res) => {
  res.json({
    ok: true,
    service: "inidan-finder-backend",
    hasXClient: Boolean(X_CLIENT_ID && X_CLIENT_SECRET && X_REDIRECT_URI),
  });
});

app.get("/", (req, res) => {
  if (process.env.PUBLIC_SITE_URL) return res.redirect(process.env.PUBLIC_SITE_URL);
  res.type("text").send("Backend is running. Try /api/status");
});

// -------------------- X Connect / Status --------------------
// Convenience route your frontend can use
app.get("/api/x/connect", (req, res) => res.redirect("/api/twitter/login"));

// For your UI: { connected: boolean, username: string|null }
app.get("/api/x/status", (req, res) => {
  const connected = Boolean(req.session?.x_access_token);
  const username = req.session?.x_username || null;
  res.json({ connected, username });
});

// -------------------- OAuth2 PKCE Login --------------------
app.get("/api/twitter/login", (req, res) => {
  try {
    requireXConfig();

    const state = base64url(crypto.randomBytes(16));
    const codeVerifier = base64url(crypto.randomBytes(32));
    const codeChallenge = sha256Base64Url(codeVerifier);

    req.session.x_oauth_state = state;
    req.session.x_code_verifier = codeVerifier;

    // ✅ Minimal scopes for "Connect + show username"
    // (avoids the X approval error when your app isn't allowed for write/offline scopes yet)
    const scopes = "users.read tweet.read";

    const authorizeUrl =
      "https://twitter.com/i/oauth2/authorize" +
      `?response_type=code` +
      `&client_id=${encodeURIComponent(X_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(X_REDIRECT_URI)}` +
      `&scope=${encodeURIComponent(scopes)}` +
      `&state=${encodeURIComponent(state)}` +
      `&code_challenge=${encodeURIComponent(codeChallenge)}` +
      `&code_challenge_method=S256`;

    return res.redirect(authorizeUrl);
  } catch (e) {
    return res.status(e.status || 400).json({ ok: false, error: e.message });
  }
});

// Callback
app.get("/api/twitter/callback", async (req, res) => {
  try {
    requireXConfig();

    const { code, state } = req.query || {};
    if (!code) return res.status(400).send("Missing code");
    if (!state) return res.status(400).send("Missing state");

    if (!req.session.x_oauth_state || state !== req.session.x_oauth_state) {
      return res.status(400).send("Invalid state");
    }
    if (!req.session.x_code_verifier) {
      return res.status(400).send("Missing code_verifier in session");
    }

    const tokenRes = await fetch("https://api.twitter.com/2/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization:
          "Basic " +
          Buffer.from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`).toString("base64"),
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: String(code),
        redirect_uri: String(X_REDIRECT_URI),
        code_verifier: String(req.session.x_code_verifier),
      }).toString(),
    });

    const tokenJson = await tokenRes.json();
    if (!tokenRes.ok) {
      return res.status(400).json({ ok: false, error: tokenJson });
    }

    req.session.x_access_token = tokenJson.access_token;
    req.session.x_token_type = tokenJson.token_type;
    req.session.x_expires_in = tokenJson.expires_in;

    // Cleanup temp PKCE/state
    delete req.session.x_oauth_state;
    delete req.session.x_code_verifier;

    // Fetch username and store for UI
    try {
      const meRes = await fetch("https://api.twitter.com/2/users/me", {
        headers: { Authorization: `Bearer ${req.session.x_access_token}` },
      });
      const meJson = await meRes.json();
      if (meRes.ok && meJson?.data?.username) {
        req.session.x_username = meJson.data.username;
        req.session.x_user_id = meJson.data.id;
      } else {
        req.session.x_username = null;
      }
    } catch (e) {
      req.session.x_username = null;
    }

    return req.session.save(() => res.redirect(TWITTER_SUCCESS_REDIRECT));
  } catch (e) {
    return res.status(500).send(`Twitter callback error: ${e.message}`);
  }
});

// -------------------- API: Me --------------------
app.get("/api/twitter/me", async (req, res) => {
  try {
    const token = await ensureXToken(req);
    const r = await fetch("https://api.twitter.com/2/users/me", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const j = await r.json();
    if (!r.ok) return res.status(400).json({ ok: false, error: j });
    res.json({ ok: true, me: j });
  } catch (e) {
    res.status(e.status || 500).json({ ok: false, error: e.message });
  }
});

// -------------------- API: Tweet (optional) --------------------
// NOTE: This will fail until you request tweet.write scope and your app is allowed.
// Keep it here for later; it's safe to leave.
app.post("/api/twitter/tweet", async (req, res) => {
  try {
    const { text } = req.body || {};
    if (!text || typeof text !== "string") {
      return res.status(400).json({ ok: false, error: "Missing text" });
    }

    const token = await ensureXToken(req);
    const r = await fetch("https://api.twitter.com/2/tweets", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ text }),
    });

    const j = await r.json();
    if (!r.ok) return res.status(400).json({ ok: false, error: j });
    res.json({ ok: true, tweet: j });
  } catch (e) {
    res.status(e.status || 500).json({ ok: false, error: e.message });
  }
});

// -------------------- Start --------------------
app.listen(PORT, () => {
  console.log(`Indian Finder API running on port ${PORT}`);







