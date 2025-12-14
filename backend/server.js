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
const PORT = process.env.PORT || 8080;

/* =====================
   ENV
===================== */
const ADMIN_SECRET = process.env.ADMIN_SECRET || "dev_admin_change_me";
const PUBLIC_SITE_URL =
  process.env.PUBLIC_SITE_URL || "http://localhost:5173";

const COOKIE_SECURE = process.env.COOKIE_SECURE === "true";
const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || "lax";

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
    secret: "fails_session_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE,
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
  if (req.session?.isAdmin) return next();
  return res.status(401).json({ ok: false, error: "Unauthorized" });
}

/* =====================
   HEALTH
===================== */
app.get("/health", (_, res) => {
  res.json({ ok: true });
});

/* =====================
   ADMIN AUTH
===================== */
app.post("/api/admin/login", (req, res) => {
  const password = String(req.body.password || "");
  if (password !== ADMIN_SECRET) {
    return res.status(401).json({ ok: false, error: "Invalid password" });
  }
  req.session.isAdmin = true;
  req.session.save(() => res.json({ ok: true }));
});

app.post("/api/admin/logout", (req, res) => {
  req.session.isAdmin = false;
  req.session.save(() => res.json({ ok: true }));
});

app.get("/api/admin/status", (req, res) => {
  res.json({ ok: true, isAdmin: !!req.session.isAdmin });
});

/* =====================
   UPLOAD FAIL (FIXED)
===================== */
app.post("/api/upload", upload.any(), (req, res) => {
  const file = req.files?.[0];

  if (!file) {
    return res.status(400).json({ ok: false, error: "No file uploaded" });
  }

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
   FAILS API
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
   STATIC FILES
===================== */
app.use("/uploads", express.static(uploadsDir));

/* =====================
   ERROR HANDLER (IMPORTANT)
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
});


