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

// ✅ REQUIRED when behind Railway proxy, especially with secure cookies
app.set("trust proxy", 1);

/* =====================
   ENV
===================== */
const PORT = process.env.PORT || 8080;

const ADMIN_SECRET = process.env.ADMIN_SECRET || "dev_admin_change_me";
const PUBLIC_SITE_URL = process.env.PUBLIC_SITE_URL || "http://localhost:5173";

const COOKIE_SECURE = process.env.COOKIE_SECURE === "true";
const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || "lax";

const DEBUG_AUTH = (process.env.DEBUG_AUTH || "true") === "true";

/* =====================
   DEBUG HELPERS
===================== */
function dlog(...args) {
  if (DEBUG_AUTH) console.log("[AUTH-DEBUG]", ...args);
}

function cookiePreview(req) {
  const raw = req.headers?.cookie || "";
  if (!raw) return "(no cookie header)";
  // avoid printing full cookie value
  return raw.replace(/fails\.sid=[^;]+/g, "fails.sid=<redacted>");
}

/* =====================
   MIDDLEWARE
===================== */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Useful request log for debugging auth
app.use((req, res, next) => {
  if (DEBUG_AUTH) {
    console.log(
      `[REQ] ${req.method} ${req.path} | origin=${req.headers.origin || ""} | ${cookiePreview(req)}`
    );
  }
  next();
});

// ✅ CORS must allow credentials + exact origin
app.use(
  cors({
    origin: PUBLIC_SITE_URL,
    credentials: true,
  })
);

app.use(
  session({
    name: "fails.sid",
    secret: process.env.SESSION_SECRET || "fails_session_secret_change_me",
    resave: false,
    saveUninitialized: false,
    proxy: true, // ✅ helps with secure cookies behind proxy
    cookie: {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE,
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
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
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${crypto.randomUUID()}${ext}`);
  },
});

const upload = multer({ storage });

/* =====================
   HELPERS
===================== */
function readVideos() {
  return JSON.parse(fs.readFileSync(videosFile, "utf8"));
}

function writeVideos(videos) {
  fs.writeFileSync(videosFile, JSON.stringify(videos, null, 2));
}

function requireAdmin(req, res, next) {
  const ok = !!req.session?.isAdmin;
  dlog("requireAdmin:", {
    ok,
    sessionID: req.sessionID,
    isAdmin: req.session?.isAdmin,
  });
  if (ok) return next();
  return res.status(401).json({ ok: false, error: "Unauthorized" });
}

/* =====================
   HEALTH
===================== */
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    port: PORT,
    cookie: {
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE,
    },
    publicSiteUrl: PUBLIC_SITE_URL,
  });
});

/* =====================
   DEBUG ENDPOINTS
===================== */
app.get("/api/debug/session", (req, res) => {
  // DO NOT use this for production long-term; it's for debugging right now.
  res.json({
    ok: true,
    origin: req.headers.origin || null,
    cookieHeaderPresent: !!req.headers.cookie,
    sessionID: req.sessionID,
    session: {
      isAdmin: !!req.session?.isAdmin,
    },
    cookieConfig: {
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE,
      publicSiteUrl: PUBLIC_SITE_URL,
      trustProxy: true,
    },
  });
});

/* =====================
   ADMIN AUTH (SESSION)
===================== */
app.post("/api/admin/login", (req, res) => {
  const password = String(req.body.password || "");
  const match = password === ADMIN_SECRET;

  dlog("login attempt:", {
    match,
    sessionID_before: req.sessionID,
    hadCookieHeader: !!req.headers.cookie,
  });

  if (!match) {
    return res.status(401).json({ ok: false, error: "Invalid password" });
  }

  req.session.isAdmin = true;

  req.session.save((err) => {
    if (err) {
      console.error("[AUTH-DEBUG] session.save error:", err);
      return res.status(500).json({ ok: false, error: "Session save failed" });
    }
    dlog("login success:", {
      sessionID_after: req.sessionID,
      isAdmin: req.session.isAdmin,
      setCookie: "should be set by express-session",
    });
    res.json({ ok: true });
  });
});

app.post("/api/admin/logout", (req, res) => {
  req.session.isAdmin = false;
  req.session.save(() => res.json({ ok: true }));
});

app.get("/api/admin/status", (req, res) => {
  dlog("status:", { sessionID: req.sessionID, isAdmin: !!req.session?.isAdmin });
  res.json({ ok: true, isAdmin: !!req.session?.isAdmin });
});

/* =====================
   UPLOAD FAIL (ACCEPTS ANY FIELD NAME)
===================== */
app.post("/api/upload", upload.any(), (req, res) => {
  const file = req.files?.[0];
  if (!file) return res.status(400).json({ ok: false, error: "No file uploaded" });

  const videos = readVideos();

  const fail = {
    id: crypto.randomUUID(),
    filename: file.filename,
    url: `/uploads/${file.filename}`,
    title: req.body.title || "",
    author: req.body.author || "",
    createdAt: Date.now(),
  };

  videos.unshift(fail);
  writeVideos(videos);

  res.json({ ok: true, fail });
});

/* =====================
   PUBLIC FAILS API
===================== */
app.get("/api/fails", (_, res) => {
  res.json(readVideos());
});

app.get("/api/fails/:id", (req, res) => {
  const fail = readVideos().find((v) => v.id === req.params.id);
  if (!fail) return res.status(404).json({ ok: false });
  res.json(fail);
});

/* =====================
   ADMIN FAIL MANAGEMENT (OPTION A)
===================== */
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

  // best-effort delete uploaded file
  try {
    const fullPath = path.join(uploadsDir, removed.filename);
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
  } catch (e) {
    console.warn("Could not delete file:", e?.message || e);
  }

  res.json({ ok: true });
});

/* =====================
   STATIC FILES
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
  console.log(`[CFG] DEBUG_AUTH=${DEBUG_AUTH}`);
});



