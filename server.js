require('dotenv').config();

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const { readDB, writeDB, nextId } = require('./db');

const app = express();

const PORT = process.env.PORT || 4000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-this-password';

app.use(cors());
app.use(express.json());

/* ---------- Uploads folder ---------- */

const uploadsDir = path.join(__dirname, 'uploads');

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

app.use('/uploads', express.static(uploadsDir));
app.use('/admin', express.static(path.join(__dirname, 'admin')));


/* ---------- Simple token-based admin auth ---------- */

const sessions = new Map();
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';

  const token = header.startsWith('Bearer ')
    ? header.slice(7)
    : null;

  const expiry = token && sessions.get(token);

  if (!expiry || expiry < Date.now()) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  next();
}


/* ---------- Admin Login ---------- */

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};

  if (
    username === ADMIN_USERNAME &&
    password === ADMIN_PASSWORD
  ) {
    const token = crypto.randomBytes(24).toString('hex');

    sessions.set(
      token,
      Date.now() + SESSION_TTL_MS
    );

    return res.json({ token });
  }

  res.status(401).json({
    error: 'Invalid username or password'
  });
});


/* ---------- Admin Logout ---------- */

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  const token = req.headers.authorization.slice(7);

  sessions.delete(token);

  res.json({
    ok: true
  });
});


/* ---------- File Upload ---------- */

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },

  filename: (req, file, cb) => {
    const safeName = file.originalname
      .replace(/\s+/g, '-')
      .replace(/[^a-zA-Z0-9._-]/g, '');

    cb(
      null,
      Date.now() + '-' + safeName
    );
  }
});

const upload = multer({
  storage
});

app.post(
  '/api/upload',
  requireAdmin,
  upload.single('file'),
  (req, res) => {

    if (!req.file) {
      return res.status(400).json({
        error: 'No file uploaded'
      });
    }

    res.json({
      url: '/uploads/' + req.file.filename
    });
  }
);


/* ---------- Generic CRUD Routes ---------- */

function crudRoutes(name) {

  // Public read
  app.get(`/api/${name}`, async (req, res) => {
    try {
      const db = await readDB();

      res.json(db[name] || []);
    } catch (error) {
      console.error(`GET /api/${name}`, error);

      res.status(500).json({
        error: 'Database error'
      });
    }
  });


  // Admin create
  app.post(`/api/${name}`, requireAdmin, async (req, res) => {
    try {
      const db = await readDB();

      if (!Array.isArray(db[name])) {
        db[name] = [];
      }

      const item = {
        id: nextId(db[name]),
        ...req.body
      };

      db[name].push(item);

      await writeDB(db);

      res.status(201).json(item);

    } catch (error) {
      console.error(`POST /api/${name}`, error);

      res.status(500).json({
        error: 'Database error'
      });
    }
  });


  // Admin update
  app.put(`/api/${name}/:id`, requireAdmin, async (req, res) => {
    try {
      const db = await readDB();

      const id = Number(req.params.id);

      if (!Array.isArray(db[name])) {
        db[name] = [];
      }

      const idx = db[name].findIndex(
        item => Number(item.id) === id
      );

      if (idx === -1) {
        return res.status(404).json({
          error: 'Not found'
        });
      }

      db[name][idx] = {
        ...db[name][idx],
        ...req.body,
        id
      };

      await writeDB(db);

      res.json(db[name][idx]);

    } catch (error) {
      console.error(`PUT /api/${name}`, error);

      res.status(500).json({
        error: 'Database error'
      });
    }
  });


  // Admin delete
  app.delete(`/api/${name}/:id`, requireAdmin, async (req, res) => {
    try {
      const db = await readDB();

      const id = Number(req.params.id);

      if (!Array.isArray(db[name])) {
        db[name] = [];
      }

      db[name] = db[name].filter(
        item => Number(item.id) !== id
      );

      await writeDB(db);

      res.json({
        ok: true
      });

    } catch (error) {
      console.error(`DELETE /api/${name}`, error);

      res.status(500).json({
        error: 'Database error'
      });
    }
  });
}


/* ---------- Admin Managed Collections ---------- */

[
  'programs',
  'events',
  'gallery',
  'documents',
  'donors'
].forEach(crudRoutes);


/* ---------- Public Submission Routes ---------- */

function submissionRoutes(name) {

  // Public form submission
  app.post(`/api/${name}`, async (req, res) => {
    try {
      const db = await readDB();

      if (!Array.isArray(db[name])) {
        db[name] = [];
      }

      const item = {
        id: nextId(db[name]),
        submittedAt: new Date().toISOString(),
        ...req.body
      };

      db[name].push(item);

      await writeDB(db);

      res.status(201).json({
        ok: true
      });

    } catch (error) {
      console.error(`POST /api/${name}`, error);

      res.status(500).json({
        error: 'Database error'
      });
    }
  });


  // Admin read
  app.get(`/api/${name}`, requireAdmin, async (req, res) => {
    try {
      const db = await readDB();

      res.json(db[name] || []);

    } catch (error) {
      console.error(`GET /api/${name}`, error);

      res.status(500).json({
        error: 'Database error'
      });
    }
  });


  // Admin delete
  app.delete(`/api/${name}/:id`, requireAdmin, async (req, res) => {
    try {
      const db = await readDB();

      const id = Number(req.params.id);

      if (!Array.isArray(db[name])) {
        db[name] = [];
      }

      db[name] = db[name].filter(
        item => Number(item.id) !== id
      );

      await writeDB(db);

      res.json({
        ok: true
      });

    } catch (error) {
      console.error(`DELETE /api/${name}`, error);

      res.status(500).json({
        error: 'Database error'
      });
    }
  });
}


/* ---------- Website Form Collections ---------- */

[
  'volunteers',
  'members',
  'contactMessages',
  'newsletter'
].forEach(submissionRoutes);


/* ---------- Main Website ---------- */

app.get('/', (req, res) => {
  res.sendFile(
    path.join(__dirname, 'index.html')
  );
});


/* ---------- Start Server ---------- */

app.listen(PORT, () => {
  console.log(
    `Nisha Seva backend running on port ${PORT}`
  );

  console.log(
    `Admin panel: /admin`
  );
});
