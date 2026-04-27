const express = require("express");
const http = require("http");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");

require('dotenv').config({ path: 'secretcode.env' });  // ← Loads secretcode.env

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Serve frontend files from "public" folder
app.use(express.static("public"));

const USERS_FILE = "users.json";
const CHAT_FILE = "chat.json";

// Load JWT_SECRET from secretcode.env
// If the variable is missing → fallback to hardcoded value (for safety during development)
const JWT_SECRET = process.env.JWT_SECRET || "kX9pQvT3mW8rZ2fL5jH7nB4cY6aD1eR0tG2uI8oPqS";

// Load users
let users = fs.existsSync(USERS_FILE)
  ? JSON.parse(fs.readFileSync(USERS_FILE))
  : {};

// Load chat history
let messages = fs.existsSync(CHAT_FILE)
  ? JSON.parse(fs.readFileSync(CHAT_FILE))
  : [];

io.on("connection", (socket) => {
  // ── REGISTER ───────────────────────────────────────
  socket.on("register", async ({ username, password }) => {
    if (!username || !password) {
      socket.emit("auth_error", "Username and password required");
      return;
    }
    if (users[username]) {
      socket.emit("auth_error", "Username already exists");
      return;
    }
    const hash = await bcrypt.hash(password, 10);
    users[username] = hash;
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    socket.emit("auth_success", "Registered successfully!");
  });

  // ── NORMAL LOGIN ───────────────────────────────────
  socket.on("login", async ({ username, password }) => {
    if (!users[username]) {
      socket.emit("auth_error", "User not found");
      return;
    }

    const ok = await bcrypt.compare(password, users[username]);
    if (!ok) {
      socket.emit("auth_error", "Wrong password");
      return;
    }

    // Create JWT token
    const token = jwt.sign(
      { username: username },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    socket.username = username;
    socket.emit("login_success", messages, token);
  });

  // ── AUTO LOGIN (using saved token) ─────────────────
  socket.on("auto_login", ({ username, token }) => {
    if (!username || !token) {
      socket.emit("auto_login_failed", "Missing credentials");
      return;
    }

    try {
      const decoded = jwt.verify(token, JWT_SECRET);

      // Check if token belongs to this user
      if (decoded.username !== username) {
        socket.emit("auto_login_failed", "Invalid token");
        return;
      }

      // Check if user still exists
      if (!users[username]) {
        socket.emit("auto_login_failed", "User no longer exists");
        return;
      }

      socket.username = username;
      socket.emit("auto_login_success", messages);
    } catch (err) {
      if (err.name === "TokenExpiredError") {
        socket.emit("auto_login_failed", "Session expired");
      } else {
        socket.emit("auto_login_failed", "Invalid token");
      }
    }
  });

  // ── NEW MESSAGE ────────────────────────────────────
  socket.on("message", (text) => {
    if (!socket.username) return;

    const msg = {
      user: socket.username,
      text,
      time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    messages.push(msg);
    fs.writeFileSync(CHAT_FILE, JSON.stringify(messages, null, 2));

    io.emit("message", msg);
  });
});

// Start server
server.listen(3000, "0.0.0.0", () => {
  console.log("Server running at http://localhost:3000");
});