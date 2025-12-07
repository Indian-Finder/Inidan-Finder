// backend/server.js
import express from "express";
import fs from "fs/promises";
import fsSync from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { randomUUID } from "crypto";
import multer from "multer";
import cors from "cors";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

// ---------- Paths / files ----------
const DATA_DIR = __dirname;               // backend folder
const MEDIA_PATH = path.join(DATA_DIR, "media.json");
const UPLOAD_ROOT = path.join(DATA_DIR, "uploads");
const VIDEO_DIR = path.join(UPLOAD_ROOT, "videos");
const IMAGE_DIR = path.join(UPLOAD_ROOT, "images");

// ensure folders exist
for (const dir of [UPLOAD_ROOT, VIDEO_DIR, IMAGE_DIR]) {
  if (!fsSync.existsSync(dir)) {
    fsSync.mkdirSync(dir, { recursive: true });
  }
}

// ---------- Helpers ----------
async function loadMedia() {
  try {
    const raw = await fs.readFile(MEDIA_PATH, "utf8");
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

async function saveMedia(items) {
  await fs.writeFile(MEDIA_PATH, JSON.stringify(items, null, 2), "utf8");
}

// ---------- Middleware ----------
app.use(cors()); // allow Netlify/front-end to call this API
app.use(express.json());

// serve uploaded files
app.use("/uploads", express.static(UPLOAD_ROOT));

// ---------- Multer upload config ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const isVideo = file.mimetype.startsWith("video");
    cb(null, isVideo ? VIDEO_DIR : IMAGE_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || "";
    const id = randomUUID();
    cb(null, `${id}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 200 * 1024 * 1024 // 200MB max
  }
});

// ---------- Routes ----------

// List of all approved media items
app.get("/api/media", async (req, res) => {
  const media = await loadMedia();
  res.json(media);
});

// Upload a new fail (video or image)
app.post("/api/upload", upload.single("file"), async (req, res) => {
  try {
    const { title } = req.body;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const isVideo = file.mimetype.startsWith("video");
    const mediaType = isVideo ? "video" : "image";

    // path the front-end will use (combined with API base URL)
    const relativePath = `/uploads/${isVideo ? "videos" : "images"}/${file.filename}`;

    const items = await loadMedia();
    const item = {
      id: "media_" + randomUUID(),
      mediaType,
      src: relativePath,
      title: title || file.originalname
    };

    items.push(item);
    await saveMedia(items);

    res.json({ ok: true, item });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Upload failed" });
  }
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`Fails API running on port ${PORT}`);
});

