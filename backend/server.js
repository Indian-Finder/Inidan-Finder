// server.js – Fails.com backend (Railway)

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const fsp = fs.promises;
const path = require("path");

// --- Config ----------------------------------------------------

const PORT = process.env.PORT || 8080;
const DATA_FILE = path.join(__dirname, "videos.json");
const UPLOAD_DIR = path.join(__dirname, "uploads");

// IMPORTANT: set this in Railway → Variables
const ADMIN_SECRET = process.env.ADMIN_SECRET || "changeme-super-secret";
console.log("ADMIN_SECRET from env is:", JSON.stringify(ADMIN_SECRET));

// --- Helpers ---------------------------------------------------

async function ensureDirs() {
  try {
    await fsp.mkdir(UPLOAD_DIR, { recursive: true });
  } catch (err) {
    console.error("Error ensuring upload dir:", err);
  }
}

async function loadMediaList() {
  try {
    const raw = await fsp.readFile(DATA_FILE, "utf8");
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr.map(normalizeItem);
  } catch (err) {
    if (err.code === "ENOENT") {
      // File does not exist yet; create empty array
      await saveMediaList([]);
      return [];
    }
    console.error("Error reading media list:", err);
    return [];
  }
}

async function saveMediaList(list) {
  try {
    await fsp.writeFile(DATA_FILE, JSON.stringify(list, null, 2), "utf8");
  } catch (err) {
    console.error("Error saving media list:", err);
  }
}

// Ensure every item has id/upvotes/status/createdAt so older files still work
function normalizeItem(item) {
  if (!item) return item;

  const clone = { ...item };

  if (!clone.id) {
    clone.id = Date.now().toString() + Math.random().toString(16).slice(2);
  }
  if (typeof clone.upvotes !== "number") {
    clone.upvotes = 0;
  }
  if (!clone.status) {
    // Old data = assume already approved
    clone.status = "approved";
  }
  if (!clone.createdAt) {
    clone.createdAt = new Date().toISOString();
  }
  return clone;
}

// --- Multer setup for uploads ----------------------------------

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOAD_DIR);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname) || "";
    const base =
      path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_-]/g, "_") ||
      "file";
    const stamp = Date.now();
    cb(null, `${base}_${stamp}${ext}`);
  },
});

const upload = multer({ storage });

// --- Admin auth middleware -------------------------------------

// --- Admin auth middleware -------------------------------------
function requireAdmin(req, res, next) {
  const secretFromHeader = req.get("x-admin-secret");
  const secretFromQuery = req.query.adminSecret;
  const provided = (secretFromHeader || secretFromQuery || "").trim();

  const expected = (process.env.ADMIN_SECRET || "changeme-super-secret").trim();

  console.log("Admin auth check:", {
    expected,
    provided,
    fromHeader: secretFromHeader,
    fromQuery: secretFromQuery
  });

  if (provided !== expected) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  console.log("Admin auth SUCCESS for:", provided);
  next();
}


// --- App setup -------------------------------------------------

const app = express();

app.use(cors()); // allow Netlify frontend to call API
app.use(express.json());

// static for uploaded media
app.use("/uploads", express.static(UPLOAD_DIR));

// health check
app.get("/", (req, res) => {
  res.send("Fails API is running");
});

// --- Public API ------------------------------------------------

// Return only APPROVED media for the main site
app.get("/api/media", async (req, res) => {
  try {
    const list = await loadMediaList();
    const approved = list.filter((item) => item.status === "approved");
    res.json(approved);
  } catch (err) {
    console.error("GET /api/media error:", err);
    res.status(500).json({ error: "Could not load media" });
  }
});

// Upload a new fail (video or image) – goes in as PENDING
app.post("/api/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const title = (req.body.title || "").trim();
    const uploader = (req.body.uploader || "").trim();
    const mime = req.file.mimetype || "";

    const mediaType = mime.startsWith("image/") ? "image" : "video";

    const mediaItem = normalizeItem({
      id: Date.now().toString(),
      mediaType,
      src: `/uploads/${req.file.filename}`,
      title,
      uploader,
      upvotes: 0,
      status: "pending",
      createdAt: new Date().toISOString(),
    });

    const list = await loadMediaList();
    list.push(mediaItem);
    await saveMediaList(list);

    res.json(mediaItem);
  } catch (err) {
    console.error("POST /api/upload error:", err);
    res.status(500).json({ error: "Upload failed" });
  }
});

// Upvote a fail
app.post("/api/media/:id/upvote", async (req, res) => {
  try {
    const id = req.params.id;
    const list = await loadMediaList();
    const item = list.find((m) => m.id === id);

    if (!item) {
      return res.status(404).json({ error: "Media not found" });
    }

    item.upvotes = (item.upvotes || 0) + 1;
    await saveMediaList(list);

    res.json(item);
  } catch (err) {
    console.error("POST /api/media/:id/upvote error:", err);
    res.status(500).json({ error: "Could not upvote" });
  }
});

// --- Admin API -------------------------------------------------

// List submissions for admin panel
// GET /api/submissions?status=pending|approved|rejected|all
app.get("/api/submissions", requireAdmin, async (req, res) => {
  try {
    const status = (req.query.status || "pending").toLowerCase();
    const list = await loadMediaList();

    let filtered = list;
    if (status !== "all") {
      filtered = list.filter((item) => item.status === status);
    }

    res.json(filtered);
  } catch (err) {
    console.error("GET /api/submissions error:", err);
    res.status(500).json({ error: "Could not load submissions" });
  }
});

// Update a submission (approve / reject)
app.patch("/api/submissions/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { status } = req.body;

    if (!status || !["pending", "approved", "rejected"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    const list = await loadMediaList();
    const item = list.find((m) => m.id === id);

    if (!item) {
      return res.status(404).json({ error: "Submission not found" });
    }

    item.status = status;
    await saveMediaList(list);

    res.json(item);
  } catch (err) {
    console.error("PATCH /api/submissions/:id error:", err);
    res.status(500).json({ error: "Could not update submission" });
  }
});

// --- Start server ----------------------------------------------

(async () => {
  await ensureDirs();
  app.listen(PORT, () => {
    console.log(`Fails API running on port ${PORT}`);
  });
})();


