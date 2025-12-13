try { require("dotenv").config(); } catch (e) {}

const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const fetch = require("node-fetch");

const app = express();
const PORT = process.env.PORT || 8080;

/* ---------------- CONFIG ---------------- */

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  process.env.PUBLIC_SITE_URL ||
  "";

const COOKIE_SECURE = String(process.env.COOKIE_SECURE || "true") === "true";
const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || "none";

const X_CLIENT_ID = process.env.X_CLIENT_ID || process.env.TWITTER_CLIENT_ID;
const X_CLIENT_SECRET =
  process.env.X_CLIENT_SECRET || process.env.TWITTER_CLIENT_SECRET;

const X_REDIRECT_URI =
  process.env.X_REDIRECT_URI || process.env.TWITTER_CALLBACK_URL;

const TWITTER_SUCCESS_REDIRECT =
  process.env.TWITTER_SUCCESS_REDIRECT ||
  FRONTEND_ORIGIN ||
  "/";

/* ---------------- MIDDLEWARE ---------------- */

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

/* ---------------- HELPERS ---------------- */

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
    throw new Error("Missing X OAuth configuration");
  }
}

async function ensureXToken(req) {
  if (!req.session?.x_access_token) {
    const err = new Error("Not connected to X");
    err.status = 401;
    throw err;
  }
  return req.session.x_access_token;
}

/* ---------------- HEALTH ---------------- */

app.get("/api/status", (req, res) => {
  res.json({ ok: true });
});

app.get("/", (req, res) => {
  if (process.env.PUBLIC_SITE_URL) return res.redirect(process.env.PUBLIC_SITE_URL);
  res.send("Backend running");
});

/* ---------------- X STATUS ---------------- */

app.get("/api/x/status", (req, res) => {
  res.json({
    connected: Boolean(req.session?.x_access_token),
    username: req.session?.x_username || null,
  });
});

app.get("/api/x/connect", (req, res) => {
  res.redirect("/api/twitter/login");
});

/* ---------------- LOGIN ---------------- */

app.get("/api/twitter/login", (req, res) => {
  try {
    requireXConfig();

    const state = base64url(crypto.randomBytes(16));
    const verifier = base64url(crypto.randomBytes(32));
    const challenge = sha256Base64Url(verifier);

    req.session.x_oauth_state = state;
    req.session.x_code_verifier = verifier;

    const scopes = "users.read tweet.read";

    const url =
      "https://twitter.com/i/oauth2/authorize" +
      `?response_type=code` +
      `&client_id=${encodeURIComponent(X_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(X_REDIRECT_URI)}` +
      `&scope=${encodeURIComponent(scopes)}` +
      `&state=${encodeURIComponent(state)}` +
      `&code_challenge=${encodeURIComponent(challenge)}` +
      `&code_challenge_method=S256`;

    res.redirect(url);
  } catch (e) {
    res.status(500).send(e.message);
  }
});

/* ---------------- CALLBACK ---------------- */

app.get("/api/twitter/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (state !== req.session.x_oauth_state) {
      return res.status(400).send("Invalid state");
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
        code,
        redirect_uri: X_REDIRECT_URI,
        code_verifier: req.session.x_code_verifier,
      }),
    });

    const token = await tokenRes.json();
    if (!token.access_token) return res.status(400).json(token);

    req.session.x_access_token = token.access_token;

    const meRes = await fetch("https://api.twitter.com/2/users/me", {
      headers: { Authorization: `Bearer ${token.access_token}` },
    });

    const me = await meRes.json();
    req.session.x_username = me?.data?.username || null;

    req.session.save(() => res.redirect(TWITTER_SUCCESS_REDIRECT));
  } catch (e) {
    res.status(500).send(e.message);
  }
});

/* ---------------- START ---------------- */

app.listen(PORT, () => {
  console.log(`Indian Finder API running on port ${PORT}`);
});








