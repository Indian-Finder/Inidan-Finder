try { require("dotenv").config(); } catch (e) {}

const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const fetch = require("node-fetch");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 8080;

// ---------- Config ----------
const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  process.env.PUBLIC_SITE_URL ||
  "";

// For OAuth redirects, Lax is safest
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || "true") === "true";
const COOKIE_SAMESITE = (process.env.COOKIE_SAMESITE || "lax").toLowerCase();

const X_CLIENT_ID = process.env.X_CLIENT_ID || process.env.TWITTER_CLIENT_ID;
const X_CLIENT_SECRET =
  process.env.X_CLIENT_SECRET || process.env.TWITTER_CLIENT_SECRET;

const X_REDIRECT_URI =
  process.env.X_REDIRECT_URI ||
  process.env.X_REDIRECT_URL || // tolerate common typo
  process.env.TWITTER_CALLBACK_URL;

const SUCCESS_REDIRECT =
  process.env.TWITTER_SUCCESS_REDIRECT ||
  FRONTEND_ORIGIN ||
  "/";

// ---------- Middleware ----------
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

if (FRONTEND_ORIGIN) {
  const cors = require("cors");
  app.use(
    cors({
      origin: FRONTEND_ORIGIN,
      credentials: true,
    })
  );
}

// ---------- Helpers ----------
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
  const missing = [];
  if (!X_CLIENT_ID) missing.push("X_CLIENT_ID");
  if (!X_REDIRECT_URI) missing.push("X_REDIRECT_URI");
  // Secret is required for confidential clients; for PKCE public clients it may be blank.
  if (missing.length) {
    const err = new Error("Missing required env vars: " + missing.join(", "));
    err.status = 500;
    throw err;
  }
}

// ---------- Routes ----------
app.get("/api/status", (req, res) => {
  res.json({
    ok: true,
    hasXClientId: Boolean(X_CLIENT_ID),
    hasXClientSecret: Boolean(X_CLIENT_SECRET),
    redirectUri: X_REDIRECT_URI || null,
    cookie: { secure: COOKIE_SECURE, sameSite: COOKIE_SAMESITE },
  });
});

app.get("/api/x/status", (req, res) => {
  res.json({
    connected: Boolean(req.session?.x_access_token),
    username: req.session?.x_username || null,
  });
});

app.get("/api/x/connect", (req, res) => res.redirect("/api/twitter/login"));

// ---------- OAuth2 PKCE Login ----------
app.get("/api/twitter/login", (req, res) => {
  try {
    requireXConfig();

    const state = base64url(crypto.randomBytes(16));
    const verifier = base64url(crypto.randomBytes(32));
    const challenge = sha256Base64Url(verifier);

    req.session.x_oauth_state = state;
    req.session.x_code_verifier = verifier;

    const scopes = "users.read tweet.read";

    const authorizeUrl =
      "https://twitter.com/i/oauth2/authorize" +
      `?response_type=code` +
      `&client_id=${encodeURIComponent(X_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(X_REDIRECT_URI)}` +
      `&scope=${encodeURIComponent(scopes)}` +
      `&state=${encodeURIComponent(state)}` +
      `&code_challenge=${encodeURIComponent(challenge)}` +
      `&code_challenge_method=S256`;

    return req.session.save(() => res.redirect(authorizeUrl));
  } catch (e) {
    return res.status(e.status || 400).json({ ok: false, error: e.message });
  }
});

// ---------- OAuth Callback ----------
app.get("/api/twitter/callback", async (req, res) => {
  try {
    requireXConfig();

    const { code, state } = req.query || {};
    if (!code) return res.status(400).send("Missing code");
    if (!state) return res.status(400).send("Missing state");

    if (!req.session.x_oauth_state) return res.status(400).send("Invalid state (no session state)");
    if (state !== req.session.x_oauth_state) return res.status(400).send("Invalid state");
    if (!req.session.x_code_verifier) return res.status(400).send("Missing code_verifier in session");

    // IMPORTANT: X token endpoint can be picky about client auth.
    // We'll send client_id (and client_secret if present) in the body.
    // If secret is present, we ALSO send Basic auth (works for confidential clients).
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: String(code),
      redirect_uri: String(X_REDIRECT_URI),
      code_verifier: String(req.session.x_code_verifier),
      client_id: String(X_CLIENT_ID),
    });

    if (X_CLIENT_SECRET) body.set("client_secret", String(X_CLIENT_SECRET));

    const headers = {
      "Content-Type": "application/x-www-form-urlencoded",
    };

    if (X_CLIENT_SECRET) {
      headers.Authorization =
        "Basic " + Buffer.from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`).toString("base64");
    }

    const tokenRes = await fetch("https://api.twitter.com/2/oauth2/token", {
      method: "POST",
      headers,
      body: body.toString(),
    });

    const tokenJson = await tokenRes.json();
    if (!tokenRes.ok) {
      // Return the upstream error for quick debugging
      return res.status(400).json({ ok: false, error: tokenJson });
    }

    req.session.x_access_token = tokenJson.access_token;
    delete req.session.x_oauth_state;
    delete req.session.x_code_verifier;

    // Fetch username
    try {
      const meRes = await fetch("https://api.twitter.com/2/users/me", {
        headers: { Authorization: `Bearer ${req.session.x_access_token}` },
      });
      const meJson = await meRes.json();
      req.session.x_username = meJson?.data?.username || null;
      req.session.x_user_id = meJson?.data?.id || null;
    } catch {
      req.session.x_username = null;
    }

    return req.session.save(() => res.redirect(SUCCESS_REDIRECT));
  } catch (e) {
    return res.status(500).send(`Twitter callback error: ${e.message}`);
  }
});

app.listen(PORT, () => {
  console.log(`Indian Finder API running on port ${PORT}`);
});
