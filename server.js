require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const { readDB, writeDB, nextId } = require('./db');

const app = express();
const PORT = process.env.PORT || 4000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-this-password';

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/admin', express.static(path.join(__dirname, 'admin')));

// ---------- File uploads (gallery images / documents) ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '-'))
});
const upload = multer({ storage });

app.post('/api/upload', requireAdmin, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({ url: '/uploads/' + req.file.filename });
});

// ---------- Simple token-based admin auth ----------
const sessions = new Map(); // token -> expiry timestamp
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const expiry = token && sessions.get(token);
  if (!expiry || expiry < Date.now()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, Date.now() + SESSION_TTL_MS);
    return res.json({ token });
  }
  res.status(401).json({ error: 'Invalid username or password' });
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  const token = req.headers.authorization.slice(7);
  sessions.delete(token);
  res.json({ ok: true });
});

// ---------- Generic CRUD factory for admin-managed collections ----------
function crudRoutes(name) {
  // Public read
  app.get(`/api/${name}`, (req, res) => {
    const db = readDB();
    res.json(db[name]);
  });

  // Admin create
  app.post(`/api/${name}`, requireAdmin, (req, res) => {
    const db = readDB();
    const item = { id: nextId(db[name]), ...req.body };
    db[name].push(item);
    writeDB(db);
    res.status(201).json(item);
  });

  // Admin update
  app.put(`/api/${name}/:id`, requireAdmin, (req, res) => {
    const db = readDB();
    const id = Number(req.params.id);
    const idx = db[name].findIndex(i => i.id === id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    db[name][idx] = { ...db[name][idx], ...req.body, id };
    writeDB(db);
    res.json(db[name][idx]);
  });

  // Admin delete
  app.delete(`/api/${name}/:id`, requireAdmin, (req, res) => {
    const db = readDB();
    const id = Number(req.params.id);
    db[name] = db[name].filter(i => i.id !== id);
    writeDB(db);
    res.json({ ok: true });
  });
}

['programs', 'events', 'gallery', 'documents', 'donors'].forEach(crudRoutes);

// ---------- Public submission endpoints (forms on the website) ----------
function submissionRoutes(name) {
  app.post(`/api/${name}`, (req, res) => {
    const db = readDB();
    const item = { id: nextId(db[name]), submittedAt: new Date().toISOString(), ...req.body };
    db[name].push(item);
    writeDB(db);
    res.status(201).json({ ok: true });
  });

  app.get(`/api/${name}`, requireAdmin, (req, res) => {
    const db = readDB();
    res.json(db[name]);
  });

  app.delete(`/api/${name}/:id`, requireAdmin, (req, res) => {
    const db = readDB();
    const id = Number(req.params.id);
    db[name] = db[name].filter(i => i.id !== id);
    writeDB(db);
    res.json({ ok: true });
  });
}

['volunteers', 'members', 'contactMessages', 'newsletter'].forEach(submissionRoutes);

app.get('/', (req, res) => {
  res.send('Nisha Seva Foundation API is running. Admin panel: /admin');
});

app.listen(PORT, () => {
  console.log(`Nisha Seva backend running on http://localhost:${PORT}`);
  console.log(`Admin panel: http://localhost:${PORT}/admin`);
});
