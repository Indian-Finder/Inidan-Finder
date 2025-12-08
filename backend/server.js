// backend/server.js
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 8080;

// ---- basic middleware ----
app.use(cors());
app.use(express.json());

// ensure uploads dir exists
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

// serve uploaded files statically
app.use("/uploads", express.static(uploadsDir));

// ---- media storage helpers ----
const MEDIA_FILE = path.join(__dirname, "media.json");

function loadMedia() {
  try {
    if (!fs.existsSync(MEDIA_FILE)) return [];
    const raw = fs.readFileSync(MEDIA_FILE, "utf8");
    if (!raw) return [];
    const data = JSON.parse(raw);
    if (!Array.isArray(data)) return [];
    return data;
  } catch (e) {
    console.error("Error reading media.json:", e);
    return [];
  }
}

function saveMedia(list) {
  try {
    fs.writeFileSync(MEDIA_FILE, JSON.stringify(list, null, 2), "utf8");
  } catch (e) {
    console.error("Error writing media.json:", e);
  }
}

// simple id generator
function createId() {
  return (
    Date.now().toString(36) +
    "-" +
    Math.random().toString(36).slice(2, 8)
  );
}

// ---- multer config ----
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || "";
    const base = path.basename(file.originalname, ext).replace(/\s+/g, "_");
    cb(null, `${Date.now()}_${base}${ext}`);
  },
});

const upload = multer({ storage });

// ---- routes ----

// health
app.get("/", (req, res) => {
  res.send("Fails API is live. Try GET /api/media or POST /api/upload.");
});

// list all media
app.get("/api/media", (req, res) => {
  const items = loadMedia();

  // make sure each item has votes and id
  const normalized = items.map((item) => ({
    votes: 0,
    ...item,
    id: item.id || createId(),
    votes: item.votes || 0,
  }));

  // if we created new ids for some older items, persist them
  saveMedia(normalized);

  res.json(normalized);
});

// upload new media
app.post("/api/upload", upload.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "File is required" });
  }

  const title = (req.body.title || "").trim();
  const author = (req.body.author || "").trim();

  const ext = path.extname(req.file.filename).toLowerCase();
  const mediaType =
    ext === ".png" || ext === ".jpg" || ext === ".jpeg" || ext === ".webp"
      ? "image"
      : "video";

  const items = loadMedia();

  const newItem = {
    id: createId(),
    title: title || "Untitled fail",
    author: author || "",
    mediaType,
    src: `/uploads/${req.file.filename}`,
    votes: 0,
    createdAt: new Date().toISOString(),
  };

  items.push(newItem);
  saveMedia(items);

  res.json(newItem);
});

// upvote endpoint
app.post("/api/media/:id/upvote", (req, res) => {
  const id = req.params.id;
  const items = loadMedia();
  const idx = items.findIndex((m) => m.id === id);

  if (idx === -1) {
    return res.status(404).json({ error: "Media not found" });
  }

  const currentVotes = items[idx].votes || 0;
  items[idx].votes = currentVotes + 1;
  saveMedia(items);

  res.json({ id, votes: items[idx].votes });
});

// ---- start server ----
app.listen(PORT, () => {
  console.log(`Fails API running on port ${PORT}`);
});


