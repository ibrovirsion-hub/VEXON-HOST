
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawn } = require("child_process");

const app = express();
const PORT = Number(process.env.PORT) || 3000;

const ROOT = __dirname;
const DATA = path.join(ROOT, "data");
const STORAGE = path.join(ROOT, "storage");
const PUBLIC = path.join(ROOT, "public");

for (const dir of [DATA, STORAGE, PUBLIC]) {
  fs.mkdirSync(dir, { recursive: true });
}

const USERS_FILE = path.join(DATA, "users.json");
const SERVERS_FILE = path.join(DATA, "servers.json");

function readJSON(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJSON(file, value) {
  const temp = file + ".tmp";
  fs.writeFileSync(temp, JSON.stringify(value, null, 2));
  fs.renameSync(temp, file);
}

let users = readJSON(USERS_FILE, []);
let servers = readJSON(SERVERS_FILE, []);

const processes = new Map();
const logs = new Map();

function addLog(id, line) {
  const list = logs.get(id) || [];
  list.push(String(line).slice(0, 2000));
  if (list.length > 300) list.shift();
  logs.set(id, list);
}

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  name: "vexon.sid",
  secret: process.env.SESSION_SECRET || "CHANGE_THIS_SECRET",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: false,
    maxAge: 1000 * 60 * 60 * 12
  }
}));

function auth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Avval tizimga kiring." });
  }
  next();
}

function ownedServer(req, res, next) {
  const server = servers.find(
    s => s.id === req.params.id && s.owner === req.session.userId
  );

  if (!server) {
    return res.status(404).json({ error: "Server topilmadi." });
  }

  req.server = server;
  next();
}

const upload = multer({
  dest: path.join(DATA, "uploads"),
  limits: { fileSize: 300 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    if (path.extname(file.originalname).toLowerCase() !== ".jar") {
      return cb(new Error("Faqat .jar fayl yuklash mumkin."));
    }
    cb(null, true);
  }
});

app.get("/api/me", (req, res) => {
  if (!req.session.userId) return res.json({ user: null });

  const user = users.find(u => u.id === req.session.userId);
  res.json({
    user: user ? { id: user.id, username: user.username } : null
  });
});

app.post("/api/register", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({
      error: "Login 3-20 belgi, faqat harf, raqam va _ bo‘lsin."
    });
  }

  if (password.length < 8 || password.length > 100) {
    return res.status(400).json({
      error: "Parol kamida 8 ta belgidan iborat bo‘lsin."
    });
  }

  if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: "Bu login band." });
  }

  const user = {
    id: crypto.randomUUID(),
    username,
    password: await bcrypt.hash(password, 12)
  };

  users.push(user);
  writeJSON(USERS_FILE, users);

  req.session.userId = user.id;
  res.json({ ok: true, username });
});

app.post("/api/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  const user = users.find(
    u => u.username.toLowerCase() === username.toLowerCase()
  );

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Login yoki parol xato." });
  }

  req.session.userId = user.id;
  res.json({ ok: true, username: user.username });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("vexon.sid");
    res.json({ ok: true });
  });
});

app.get("/api/servers", auth, (req, res) => {
  const result = servers
    .filter(s => s.owner === req.session.userId)
    .map(s => ({
      ...s,
      status: processes.has(s.id) ? "online" : "offline"
    }));

  res.json(result);
});

app.post("/api/servers", auth, upload.single("jar"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "Minecraft .jar faylini yuklang." });
  }

  if (req.body.eula !== "yes") {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({
      error: "Minecraft EULA shartlarini qabul qilishingiz kerak."
    });
  }

  const name = String(req.body.name || "").trim();
  const ram = Number(req.body.ram);

  if (!/^[a-zA-Z0-9 _-]{3,30}$/.test(name)) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: "Server nomi noto‘g‘ri." });
  }

  if (![512, 1024, 1536, 2048].includes(ram)) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: "RAM miqdori noto‘g‘ri." });
  }

  const id = crypto.randomUUID();
  const folder = path.join(STORAGE, id);
  fs.mkdirSync(folder, { recursive: true });

  fs.renameSync(req.file.path, path.join(folder, "server.jar"));
  fs.writeFileSync(path.join(folder, "eula.txt"), "eula=true\n");

  const server = {
    id,
    owner: req.session.userId,
    name,
    ram,
    version: String(req.body.version || "Noma'lum").slice(0, 20),
    software: String(req.body.software || "Paper").slice(0, 20),
    createdAt: new Date().toISOString()
  };

  servers.push(server);
  writeJSON(SERVERS_FILE, servers);

  res.json({ ok: true, server });
});

function startMinecraft(server) {
  if (processes.has(server.id)) {
    throw new Error("Server allaqachon ishlayapti.");
  }

  const folder = path.join(STORAGE, server.id);
  const jar = path.join(folder, "server.jar");

  if (!fs.existsSync(jar)) {
    throw new Error("server.jar fayli topilmadi.");
  }

  // Shell ishlatilmaydi: faqat Java va belgilangan Minecraft argumentlari.
  const child = spawn("java", [
    `-Xms512M`,
    `-Xmx${server.ram}M`,
    "-jar",
    "server.jar",
    "nogui"
  ], {
    cwd: folder,
    windowsHide: true,
    shell: false
  });

  processes.set(server.id, child);
  addLog(server.id, "[VEXON] Server ishga tushmoqda...");

  child.stdout.on("data", data => {
    for (const line of data.toString().split(/\r?\n/)) {
      if (line.trim()) addLog(server.id, line);
    }
  });

  child.stderr.on("data", data => {
    for (const line of data.toString().split(/\r?\n/)) {
      if (line.trim()) addLog(server.id, "[ERROR] " + line);
    }
  });

  child.on("error", error => {
    addLog(server.id, "[VEXON ERROR] " + error.message);
    processes.delete(server.id);
  });

  child.on("close", code => {
    addLog(server.id, `[VEXON] Server to‘xtadi. Kod: ${code}`);
    processes.delete(server.id);
  });
}

app.post("/api/servers/:id/start", auth, ownedServer, (req, res) => {
  try {
    if (processes.size >= 1) {
      return res.status(400).json({
        error: "Hozircha bir vaqtda faqat bitta server ishlatish mumkin."
      });
    }

    startMinecraft(req.server);
    res.json({ ok: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post("/api/servers/:id/stop", auth, ownedServer, (req, res) => {
  const child = processes.get(req.server.id);

  if (!child) {
    return res.status(400).json({ error: "Server ishlamayapti." });
  }

  child.stdin.write("stop\n");
  res.json({ ok: true });
});

app.post("/api/servers/:id/restart", auth, ownedServer, (req, res) => {
  const child = processes.get(req.server.id);

  if (!child) {
    return res.status(400).json({ error: "Avval serverni ishga tushiring." });
  }

  child.stdin.write("stop\n");

  child.once("close", () => {
    try {
      startMinecraft(req.server);
    } catch (error) {
      addLog(req.server.id, "[VEXON ERROR] " + error.message);
    }
  });

  res.json({ ok: true });
});

app.get("/api/servers/:id/logs", auth, ownedServer, (req, res) => {
  res.json({
    logs: logs.get(req.server.id) || [],
    status: processes.has(req.server.id) ? "online" : "offline"
  });
});

app.post("/api/servers/:id/command", auth, ownedServer, (req, res) => {
  const child = processes.get(req.server.id);
  const command = String(req.body.command || "").trim();

  if (!child) {
    return res.status(400).json({ error: "Server ishlamayapti." });
  }

  if (!command || command.length > 200) {
    return res.status(400).json({ error: "Buyruq noto‘g‘ri." });
  }

  // Bu Minecraft konsoliga buyruq yuboradi, Windows terminaliga emas.
  child.stdin.write(command + "\n");
  res.json({ ok: true });
});

app.delete("/api/servers/:id", auth, ownedServer, (req, res) => {
  const child = processes.get(req.server.id);

  if (child) {
    child.stdin.write("stop\n");
  }

  const folder = path.join(STORAGE, req.server.id);

  servers = servers.filter(s => s.id !== req.server.id);
  writeJSON(SERVERS_FILE, servers);

  // Ishlayotgan jarayon to‘xtagach uning papkasini tozalash xavfsizroq.
  const removeFolder = () => {
    fs.rmSync(folder, { recursive: true, force: true });
  };

  if (child) child.once("close", removeFolder);
  else removeFolder();

  res.json({ ok: true });
});

app.use(express.static(PUBLIC));

app.use((err, req, res, next) => {
  res.status(400).json({
    error: err.message || "Noma’lum xatolik."
  });
});

// Faqat shu kompyuterning o‘zida ochiladi.
app.listen(PORT, "127.0.0.1", () => {
  console.log(`VEXON HOST: http://127.0.0.1:${PORT}`);
});
