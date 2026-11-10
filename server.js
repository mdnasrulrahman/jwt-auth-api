// server.js
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());
const SECRET = process.env.JWT_SECRET || "change_me";

const users = [];     // demo ke liye; baad mein MongoDB/PostgreSQL
const expenses = [];

// Register
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  users.push({ username, password: hashed });
  res.status(201).json({ message: "User created" });
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign({ username }, SECRET, { expiresIn: "1h" });
  res.json({ token });
});

// Middleware: token check
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(403).json({ error: "Invalid token" });
  }
}

// Protected routes
app.post("/expenses", auth, (req, res) => {
  const item = { user: req.user.username, ...req.body };
  expenses.push(item);
  res.status(201).json(item);
});

app.get("/expenses", auth, (req, res) => {
  res.json(expenses.filter(e => e.user === req.user.username));
});

app.listen(3000, () => console.log("Server running on port 3000"));