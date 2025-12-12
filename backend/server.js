require("dotenv").config();
const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const fetch = require("node-fetch");

const app = express();
const PORT = process.env.PORT || 8080;

/* -------------------- middleware -------------------- */
app.use(express.json());
app.use(cookieParser());

app.use(
  session({
    name: "fails.sid",
    secret: process.env.ADMIN_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: process.env.COOKIE_SECURE === "true",
      sameSite: process.env.COOKIE_SAMESITE || "none",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    },
  })
);

/* -------------------- helpers -------------------- */
function base64url(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function sha256(str) {
  return crypto.createHash("sha256").update(str).digest();
}

/* -------------------- core routes -------------------- */

// session check
app.get("/api/me", (req, res) => {
  if (!req.session.failsUserId) {
    req.session.failsUserId = crypto.randomBytes(16).toString("hex");
  }

  res.json({
    failsUserId: req.session.failsUserId,
    xConnected: !!req.session.xUser,
    xUser: req.session.xUser || null,
  });
});

/* -------------------- X OAuth START -------------------- */
app.get("/auth/x", (req, res) => {
  const clientId = process.env.X_CLIENT_ID;
  const redirectUri = process.env.X_REDIRECT_URI;

  if (!clientId || !redirectUri) {
    return res.status(500).send("Missing X OAuth environment variables");
  }

  const state = base64url(crypto.randomBytes(24));
  const codeVerifier = base64url(crypto.randomBytes(32));
  const codeChallenge = base64url(sha256(codeVerifier));

  res.cookie("x_oauth_state", state, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 10 * 60 * 1000,
  });

  res.cookie("x_code_verifier", codeVerifier, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 10 * 60 * 1000,
  });

  const scope = encodeURIComponent(
    "tweet.read tweet.write users.read offline.access"
  );

  const authUrl =
    `https://x.com/i/oauth2/authorize` +
    `?response_type=code` +
    `&client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=${scope}` +
    `&state=${encodeURIComponent(state)}` +
    `&code_challenge=${encodeURIComponent(codeChallenge)}` +
    `&code_challenge_method=S256`;

  res.redirect(authUrl);
});

/* -------------------- X OAuth CALLBACK -------------------- */
app.get("/auth/x/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    const storedState = req.cookies.x_oauth_state;
    const codeVerifier = req.cookies.x_code_verifier;

    if (!code || !state || state !== storedState) {
      return res.status(400).send("Invalid OAuth state");
    }

    // exchange code → token
    const tokenRes = await fetch("https://api.x.com/2/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: process.env.X_CLIENT_ID,
        redirect_uri: process.env.X_REDIRECT_URI,
        code,
        code_verifier: codeVerifier,
      }),
    });

    const tokenData = await tokenRes.json();

    if (!tokenData.access_token) {
      console.error("Token error:", tokenData);
      return res.status(500).send("Failed to get X access token");
    }

    // fetch user
    const userRes = await fetch("https://api.x.com/2/users/me", {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    });

    const userData = await userRes.json();

    if (!userData.data) {
      return res.status(500).send("Failed to fetch X user");
    }

    req.session.xUser = {
      id: userData.data.id,
      username: userData.data.username,
      name: userData.data.name,
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
    };

    res.clearCookie("x_oauth_state");
    res.clearCookie("x_code_verifier");

    res.redirect(process.env.PUBLIC_SITE_URL || "/");
  } catch (err) {
    console.error(err);
    res.status(500).send("X OAuth callback failed");
  }
});

/* -------------------- start -------------------- */
app.listen(PORT, () => {
  console.log(`Fails API running on port ${PORT}`);
});




