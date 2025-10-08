// server.js
const express = require("express");
const http = require("http");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");
const multer = require("multer");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Config
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "change_this_in_production";

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 3600 * 1000 },
  })
);

// Database (better-sqlite3)
const dbPath = path.join(__dirname, "chat.db");
const db = new Database(dbPath);

// Create tables if missing
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  is_admin INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS friends (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  friend_id INTEGER NOT NULL,
  UNIQUE(user_id, friend_id)
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL,
  receiver_id INTEGER NOT NULL,
  message TEXT,
  image_url TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

const adminUser = db.prepare("SELECT id FROM users WHERE username = ?").get("admin");
const hash = bcrypt.hashSync("12345", 10);
if (!adminUser) {
  db.prepare("INSERT INTO users (username, password_hash, display_name, is_admin) VALUES (?, ?, ?, 1)")
    .run("admin", hash, "Admin");
} else {
  db.prepare("UPDATE users SET password_hash = ?, is_admin = 1 WHERE username = ?")
    .run(hash, "admin");
}

// Multer for uploads
const uploadsDir = path.join(__dirname, "public", "uploads");
const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

// Helpers
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    if (req.accepts("html")) return res.redirect("/login.html");
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

// --- Routes ---

// return current user info (for client)
app.get("/me", (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  const row = db
    .prepare("SELECT id, username, display_name, is_admin FROM users WHERE id = ?")
    .get(req.session.userId);
  if (!row) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, user: row });
});

// Register (expects JSON or form)
app.post("/register", async (req, res) => {
  const { username, password, display_name } = req.body || {};
  if (!username || !password) return res.status(400).json({ success: false, message: "username/password required" });
  try {
    const hash = await bcrypt.hash(password, 10);
    const info = db.prepare("INSERT INTO users(username, password_hash, display_name) VALUES (?, ?, ?)").run(username, hash, display_name || username);
    req.session.userId = info.lastInsertRowid;
    // respond JSON (client uses fetch)
    return res.json({ success: true });
  } catch (err) {
    if (err && err.code === "SQLITE_CONSTRAINT_UNIQUE") return res.json({ success: false, message: "Username already exists" });
    console.error("Register error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Register admin
app.post("/register-admin", async (req, res) => {
  const { username, password, display_name } = req.body;
  if (!username || !password) return res.json({ error: "Missing fields" });

  const exists = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
  if (exists) return res.json({ error: "Username taken" });

  const hash = await bcrypt.hash(password, 10);

  const info = db.prepare(
    "INSERT INTO users (username, password_hash, display_name, is_admin) VALUES (?, ?, ?, 1)"
  ).run(username, hash, display_name || null);

  req.session.userId = info.lastInsertRowid;
  res.json({ ok: true, is_admin: 1 });
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ success: false, message: "username/password required" });
  const row = db.prepare("SELECT id, password_hash, display_name, is_admin FROM users WHERE username = ?").get(username);
  if (!row) return res.json({ success: false, message: "Invalid username or password" });
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return res.json({ success: false, message: "Invalid username or password" });
  req.session.userId = row.id;
  return res.json({ success: true, is_admin: row.is_admin });
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// Get all other users + friend status
app.get("/users", requireLogin, (req, res) => {
  const allUsers = db.prepare("SELECT id, username, display_name FROM users").all();
  // Optionally, mark friends for the current user
  const friends = db.prepare("SELECT friend_id FROM friends WHERE user_id = ?").all(req.session.userId).map(f => f.friend_id);
  const users = allUsers.map(u => ({
    ...u,
    isFriend: friends.includes(u.id)
  }));
  res.json(users);
});

// Add friend (one-way)
app.post("/add-friend", requireLogin, (req, res) => {
  const me = req.session.userId;
  const friendId = Number(req.body.friendId || req.body.friendId);
  if (!friendId) return res.status(400).json({ error: "missing friendId" });
  try {
    db.prepare("INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)").run(me, friendId);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get friends list
app.get("/friends", requireLogin, (req, res) => {
  const me = req.session.userId;
  const rows = db.prepare(`
    SELECT u.id, u.username, u.display_name
    FROM users u
    JOIN friends f ON u.id = f.friend_id
    WHERE f.user_id = ?
  `).all(me);
  res.json(rows);
});

// Get conversation history with another user
app.get("/messages", requireLogin, (req, res) => {
  const me = req.session.userId;
  const other = Number(req.query.with);
  if (!other) return res.status(400).json({ error: "missing 'with' param" });
  const rows = db.prepare(`
    SELECT m.*, s.username AS sender_username, r.username AS receiver_username
    FROM messages m
    LEFT JOIN users s ON s.id = m.sender_id
    LEFT JOIN users r ON r.id = m.receiver_id
    WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
    ORDER BY timestamp ASC
  `).all(me, other, other, me);
  res.json(rows);
});

// Upload image
app.post("/upload", requireLogin, upload.single("image"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  const url = "/uploads/" + req.file.filename;
  res.json({ imageUrl: url });
});

// --- Socket.io realtime private messaging ---
const userSocketMap = new Map(); // userId -> socketId

io.on("connection", (socket) => {
  console.log("socket connected:", socket.id);

  socket.on("registerSocket", (user) => {
    if (!user || !user.id) return;
    userSocketMap.set(Number(user.id), socket.id);
    io.emit("onlineUpdate", Array.from(userSocketMap.keys()));
  });

  socket.on("privateMessage", (payload) => {
    // payload: { from, to, text, imageUrl }
    const { from, to, text, imageUrl } = payload || {};
    if (!from || !to) return;
    const info = db.prepare("INSERT INTO messages (sender_id, receiver_id, message, image_url) VALUES (?, ?, ?, ?)").run(from, to, text || null, imageUrl || null);
    const msg = {
      id: info.lastInsertRowid,
      sender_id: from,
      receiver_id: to,
      message: text || null,
      image_url: imageUrl || null,
      timestamp: new Date().toISOString()
    };
    // send to recipient if online
    const toSocket = userSocketMap.get(Number(to));
    if (toSocket) io.to(toSocket).emit("incomingMessage", msg);
    // send back to sender
    socket.emit("incomingMessage", msg);
  });

  socket.on("disconnect", () => {
    for (const [uid, sid] of userSocketMap.entries()) {
      if (sid === socket.id) userSocketMap.delete(uid);
    }
    io.emit("onlineUpdate", Array.from(userSocketMap.keys()));
    console.log("socket disconnected:", socket.id);
  });
});

// Middleware to check if user is admin
function requireAdmin(req, res, next) {
  const user = db.prepare("SELECT is_admin FROM users WHERE id = ?").get(req.session.userId);
  if (!user || !user.is_admin) return res.status(403).json({ error: "admin only" });
  next();
}

// Route for admin to delete accounts
app.post("/admin/delete-user", requireLogin, requireAdmin, (req, res) => {
  const userId = Number(req.body.userId);
  if (!userId) return res.status(400).json({ error: "missing userId" });
  if (userId === req.session.userId) return res.status(400).json({ error: "cannot delete yourself" });
  db.prepare("DELETE FROM users WHERE id = ?").run(userId);
  db.prepare("DELETE FROM friends WHERE user_id = ? OR friend_id = ?").run(userId, userId);
  db.prepare("DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?").run(userId, userId);
  res.json({ ok: true });
});

// Start server
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
