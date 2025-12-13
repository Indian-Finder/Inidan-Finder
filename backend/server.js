try { require("dotenv").config(); } catch (e) {}

const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const crypto = require("crypto");
const fetch = require("node-fetch");

const app = express();
const PORT = process.env.PORT || 8080;

// ---- CORS (so your frontend can call backend w/ cookies) ----
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "*";
app.use(
  cors({
    origin: FRONTEND_ORIGIN === "*" ? true : FRONTEND_ORIGIN,
    credentials: true,
  })
);

app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

// If you're behind Railway / proxies, this helps secure cookies work properly:
app.set("trust proxy", 1);

// ---- Sessions (stores OAuth state + tokens) ----
app.use(
  session({
    name: "fails.sid",
    secret: process.env.ADMIN_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: process.env.COOKIE_SECURE === "true", // set true on Railway
      sameSite: process.env.COOKIE_SAMESITE || "none", // "none" for cross-site
      maxAge: 30 * 24 * 60 * 60 * 1000,
    },
  })
);

// -------------------- helpers --------------------
function base64url(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}
function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

const TW_CLIENT_ID = process.env.TWITTER_CLIENT_ID;
const TW_CLIENT_SECRET = process.env.TWITTER_CLIENT_SECRET; // optional depending on your app type
const TW_CALLBACK = process.env.TWITTER_CALLBACK_URL;
const TW_SCOPES =
  process.env.TWITTER_SCOPES || "tweet.read tweet.write users.read offline.access";

// Token refresh helper (OAuth2)
async function ensureTwitterToken(req) {
  const t = req.session.twitter;
  if (!t?.access_token) throw new Error("Not connected to Twitter");

  // If we have expiry info and it's still valid, good.
  if (t.expires_at && Date.now() < t.expires_at - 30_000) return t.access_token;

  // Refresh if possible
  if (!t.refresh_token) return t.access_token;

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: t.refresh_token,
    client_id: TW_CLIENT_ID,
  });

  // If your app is "confidential", Twitter wants basic auth too:
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (TW_CLIENT_SECRET) {
    const basic = Buffer.from(`${TW_CLIENT_ID}:${TW_CLIENT_SECRET}`).toString("base64");
    headers.Authorization = `Basic ${basic}`;
  }

  const r = await fetch("https://api.twitter.com/2/oauth2/token", {
    method: "POST",
    headers,
    body,
  });
  const j = await r.json();
  if (!r.ok) throw new Error(j?.error_description || j?.error || "Refresh failed");

  const expiresIn = (j.expires_in || 7200) * 1000;
  req.session.twitter = {
    ...t,
    access_token: j.access_token,
    refresh_token: j.refresh_token || t.refresh_token,
    expires_at: Date.now() + expiresIn,
  };
  return req.session.twitter.access_token;
}

// -------------------- routes --------------------
app.get("/api/status", (req, res) => {
  res.json({
    ok: true,
    message: "API is running",
    hasTwitterClientId: !!TW_CLIENT_ID,
    hasTwitterCallback: !!TW_CALLBACK,
    frontendOrigin: FRONTEND_ORIGIN,
  });
});

// -------- TWITTER: start login (OAuth2 PKCE) --------
app.get("/api/twitter/login", (req, res) => {
  if (!TW_CLIENT_ID || !TW_CALLBACK) {
    return res.status(400).json({
      ok: false,
      error: "Missing TWITTER_CLIENT_ID or TWITTER_CALLBACK_URL",
    });
  }

  const codeVerifier = base64url(crypto.randomBytes(32));
  const codeChallenge = base64url(sha256(codeVerifier));
  const state = base64url(crypto.randomBytes(16));

  req.session.twitter_oauth = { codeVerifier, state };

  const params = new URLSearchParams({
    response_type: "code",
    client_id: TW_CLIENT_ID,
    redirect_uri: TW_CALLBACK,
    scope: TW_SCOPES,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });

  const url = `https://twitter.com/i/oauth2/authorize?${params.toString()}`;
  res.json({ ok: true, url });
});

// -------- TWITTER: callback (exchange code for tokens) --------
app.get("/api/twitter/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) return res.status(400).send("Missing code");

    const oauth = req.session.twitter_oauth;
    if (!oauth?.codeVerifier) return res.status(400).send("Missing session verifier");
    if (oauth.state !== state) return res.status(400).send("State mismatch");

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: String(code),
      redirect_uri: TW_CALLBACK,
      client_id: TW_CLIENT_ID,
      code_verifier: oauth.codeVerifier,
    });

    const headers = { "Content-Type": "application/x-www-form-urlencoded" };
    if (TW_CLIENT_SECRET) {
      const basic = Buffer.from(`${TW_CLIENT_ID}:${TW_CLIENT_SECRET}`).toString("base64");
      headers.Authorization = `Basic ${basic}`;
    }

    const r = await fetch("https://api.twitter.com/2/oauth2/token", {
      method: "POST",
      headers,
      body,
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j?.error_description || j?.error || "Token exchange failed");

    const expiresIn = (j.expires_in || 7200) * 1000;
    req.session.twitter = {
      access_token: j.access_token,
      refresh_token: j.refresh_token,
      expires_at: Date.now() + expiresIn,
    };

    // optional: send user back to your frontend
    const redirectTo = process.env.TWITTER_SUCCESS_REDIRECT || FRONTEND_ORIGIN;
    return res.redirect(redirectTo);
  } catch (e) {
    return res.status(500).send(`Twitter callback error: ${e.message}`);
  }
});

app.get("/api/twitter/me", async (req, res) => {
  try {
    const token = await ensureTwitterToken(req);
    const r = await fetch("https://api.twitter.com/2/users/me", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const j = await r.json();
    if (!r.ok) return res.status(400).json({ ok: false, error: j });
    res.json({ ok: true, me: j });
  } catch (e) {
    res.status(401).json({ ok: false, error: e.message });
  }
});

// Post a tweet (text only)
app.post("/api/twitter/tweet", async (req, res) => {
  try {
    const { text } = req.body || {};
    if (!text || typeof text !== "string") {
      return res.status(400).json({ ok: false, error: "Missing text" });
    }

    const token = await ensureTwitterToken(req);
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
    res.status(401).json({ ok: false, error: e.message });
  }
});

app.post("/api/twitter/logout", (req, res) => {
  req.session.twitter = null;
  req.session.twitter_oauth = null;
  res.json({ ok: true });
});

// Root
app.get("/", (req, res) => res.send("Backend is running. Try /api/status"));

app.listen(PORT, () => {
  console.log(`Fails API running on port ${PORT}`);
});






