require('dotenv').config();

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const {
  readDB,
  readCollection,
  writeDB,
  nextId,
  pool
} = require('./db');

const {
  createClient
} = require('@supabase/supabase-js');


/* =========================================================
   REQUIRED SERVER CONFIGURATION
   ========================================================= */
const requiredEnv = [
  'DATABASE_URL',
  'ADMIN_USERNAME',
  'ADMIN_PASSWORD',
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY'
];
const missingEnv = requiredEnv.filter((key) => !String(process.env[key] || '').trim());
if (missingEnv.length) {
  throw new Error(`Missing required environment variables: ${missingEnv.join(', ')}. Configure them in Hostinger Environment; do not commit secrets.`);
}
if (String(process.env.ADMIN_PASSWORD).length < 12) {
  throw new Error('ADMIN_PASSWORD must be at least 12 characters long.');
}

/* =========================================================
   SUPABASE
   ========================================================= */
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false } }
);


/* =========================================================
   APP CONFIG
   ========================================================= */

const app = express();

// Hostinger routes requests through one reverse proxy. Trust exactly one hop so
// express-rate-limit can read the forwarded client IP without trusting arbitrary
// client-supplied proxy chains. Keep this before all rate-limit middleware.
app.set('trust proxy', 1);

// Low-overhead API timing: logs only slow request path + status + duration.
// Query strings, request bodies, tokens and personal data are never logged.
app.use((req, res, next) => {
  if (!req.path.startsWith('/api/')) return next();
  const startedAt = process.hrtime.bigint();
  res.once('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
    if (durationMs >= 750) {
      console.warn(`[API SLOW] ${req.method} ${req.route?.path || req.path} status=${res.statusCode} duration=${durationMs.toFixed(1)}ms poolTotal=${pool.totalCount} poolIdle=${pool.idleCount} poolWaiting=${pool.waitingCount}`);
    }
  });
  next();
});

// Security headers. CSP is disabled because the existing HTML uses inline scripts
// and trusted CDN assets; enable a nonce-based CSP before removing this exception.
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please wait 15 minutes and try again.' }
});
const publicFormLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many requests. Please wait and try again.' }
});

const PORT =
  process.env.PORT || 4000;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// Set both values in Hostinger Environment for a separate coordinator account.
const COORDINATOR_USERNAME = process.env.COORDINATOR_USERNAME || '';
const COORDINATOR_PASSWORD = process.env.COORDINATOR_PASSWORD || '';
const SECRETARY_USERNAME = process.env.SECRETARY_USERNAME || '';
const SECRETARY_PASSWORD = process.env.SECRETARY_PASSWORD || '';

// Treasurer username is intentionally fixed as requested; set only the password in Hostinger.
const TREASURER_USERNAME = 'NISHASEVA';
const TREASURER_PASSWORD = process.env.TREASURER_PASSWORD || '';

const PUBLIC_BASE_URL =
  process.env.PUBLIC_BASE_URL ||
  'https://api.nishasevafoundation.org';
   


/* =========================================================
   MIDDLEWARE
   ========================================================= */

// CORS: allow the production website on both apex and www hosts.
// ALLOWED_ORIGINS can add extra trusted origins, but cannot remove these defaults.
const defaultAllowedOrigins = [
  'https://nishasevafoundation.org',
  'https://www.nishasevafoundation.org',
  // The admin panel is also served from this API host (/admin).
  'https://api.nishasevafoundation.org'
];
const configuredAllowedOrigins = String(process.env.ALLOWED_ORIGINS || '')
  .split(',').map(value => value.trim()).filter(Boolean);
const allowedOrigins = [...new Set([...defaultAllowedOrigins, ...configuredAllowedOrigins])];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    console.warn('CORS blocked origin:', origin);
    return callback(null, false);
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  optionsSuccessStatus: 204,
  maxAge: 86400
}));
// Explicit preflight response for browsers sending Authorization headers.
app.options('*', cors({
  origin: (origin, callback) => callback(null, !origin || allowedOrigins.includes(origin)),
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  optionsSuccessStatus: 204,
  maxAge: 86400
}));

// Lightweight API diagnostic. Does not expose credentials or database contents.
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    return res.json({ success: true, service: 'nisha-seva-api', database: 'connected' });
  } catch (error) {
    console.error('API HEALTH CHECK ERROR:', error);
    return res.status(503).json({ success: false, service: 'nisha-seva-api', database: 'unavailable' });
  }
});

app.use(
  express.json({
    limit: '30mb',
    verify: (req, res, buf) => { if (req.originalUrl && req.originalUrl.startsWith('/api/donations/webhook')) req.rawBody = Buffer.from(buf); }
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: '30mb'
  })
);


/* =========================================================
   LOCAL UPLOADS
   ========================================================= */

const uploadsDir =
  path.join(
    __dirname,
    'uploads'
  );

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(
    uploadsDir,
    {
      recursive: true
    }
  );
}

app.use(
  '/uploads',
  express.static(uploadsDir)
);

app.use(
  '/admin',
  express.static(
    path.join(
      __dirname,
      'admin'
    )
  )
);

// Student Portal is hosted with the public website. When this backend/API
// subdomain receives the same page URL, send the browser to the canonical
// public-site page and preserve QR profile query strings.
app.get('/student-portal.html', (req, res) => {
  const queryIndex = String(req.originalUrl || '').indexOf('?');
  const query = queryIndex >= 0 ? req.originalUrl.slice(queryIndex) : '';
  return res.redirect(302, `https://nishasevafoundation.org/student-portal.html${query}`);
});


/* =========================================================
   ADMIN AUTH
   ========================================================= */

const sessions =
  new Map();

const SESSION_TTL_MS =
  12 * 60 * 60 * 1000;


function requireAdmin(
  req,
  res,
  next
) {

  const header =
    req.headers.authorization || '';

  const token =
    header.startsWith('Bearer ')
      ? header.slice(7)
      : null;

  const session = token && sessions.get(token);

  if (!session || session.expiresAt < Date.now()) {
    if (token) sessions.delete(token);
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Coordinator can access only internship application endpoints.
  if (session.role === 'coordinator' && !(
    /^\/api\/internships(?:\/|$)/.test(req.path) ||
    req.path === '/api/admin/logout' ||
    req.path === '/api/student/accounts' ||
    /^\/api\/projectSubmissions(?:\/|$)/.test(req.path) ||
    /^\/api\/certificates(?:\/|$)/.test(req.path) ||
    /^\/api\/admin\/student-impact(?:\/|$)/.test(req.path)
  )) {
    return res.status(403).json({ error: 'Forbidden: coordinator access is limited to internship management' });
  }

  if (session.role === 'secretary') {
    const allowedPath = new Set(['/api/admin/logout','/api/members','/api/volunteers','/api/secretary/records','/api/secretary/member-requests','/api/secretary/documents']).has(req.path) ||
      /^\/api\/secretary\/documents\/\d+\/download$/.test(req.path);
    if (!allowedPath) return res.status(403).json({ error: 'Forbidden: General Secretary access is limited to Secretariat functions.' });
    if ((req.path === '/api/members' || req.path === '/api/volunteers') && req.method !== 'GET') return res.status(403).json({ error: 'General Secretary can only view applications and records.' });
    if (req.path === '/api/secretary/records' && !['GET','POST'].includes(req.method)) return res.status(403).json({ error: 'This Secretariat action is not permitted.' });
    if (req.path === '/api/secretary/member-requests' && req.method !== 'POST') return res.status(403).json({ error: 'This Secretariat action is not permitted.' });
  }

  if (!['admin','coordinator','treasurer','secretary'].includes(session.role) || (session.role === 'treasurer' && req.path !== '/api/admin/logout')) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  req.userRole = session.role;
  next();
}

/* =========================================================
   STUDENT IMPACT SUITE ROUTES
   ========================================================= */
// Register after requireAdmin is defined so all admin routes use the same session auth.
const registerStudentImpactRoutes = require('./student-impact-routes');
registerStudentImpactRoutes({ app, pool, requireAdmin, publicFormLimiter });


/* =========================================================
   ADMIN LOGIN
   ========================================================= */

app.post(
  '/api/admin/login',
  authLimiter,
  (req, res) => {

    const {
      username,
      password
    } = req.body || {};

    if (
      username === ADMIN_USERNAME &&
      password === ADMIN_PASSWORD
    ) {

      const token =
        crypto.randomBytes(24)
          .toString('hex');

      sessions.set(token, { expiresAt: Date.now() + SESSION_TTL_MS, role: 'admin' });

      return res.json({ token, role: 'admin' });

    }

    res.status(401).json({
      error:
        'Invalid username or password'
    });

  }
);


/* =========================================================
   COORDINATOR LOGIN — internship-only access
   ========================================================= */
app.post('/api/coordinator/login', authLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!COORDINATOR_USERNAME || !COORDINATOR_PASSWORD) {
    return res.status(503).json({ error: 'Coordinator account is not configured. Set COORDINATOR_USERNAME and COORDINATOR_PASSWORD in Hostinger Environment.' });
  }
  if (username !== COORDINATOR_USERNAME || password !== COORDINATOR_PASSWORD) {
    return res.status(401).json({ error: 'Invalid coordinator username or password' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { expiresAt: Date.now() + SESSION_TTL_MS, role: 'coordinator' });
  return res.json({ token, role: 'coordinator' });
});


/* =========================================================
   SECRETARY LOGIN — least-privilege Secretariat workspace
   ========================================================= */
app.post('/api/secretary/login', authLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!SECRETARY_USERNAME || !SECRETARY_PASSWORD) {
    return res.status(503).json({ error: 'General Secretary account is not configured. Set SECRETARY_USERNAME and SECRETARY_PASSWORD in Hostinger Environment.' });
  }
  if (String(username || '').trim() !== SECRETARY_USERNAME || String(password || '') !== SECRETARY_PASSWORD) {
    return res.status(401).json({ error: 'Invalid General Secretary username or password.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { expiresAt: Date.now() + SESSION_TTL_MS, role: 'secretary' });
  return res.json({ token, role: 'secretary' });
});


/* =========================================================
   TREASURER LOGIN — finance-only access
   Username is fixed to NISHASEVA; password is configured privately in Hostinger.
   ========================================================= */
app.post('/api/treasurer/login', authLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!TREASURER_PASSWORD) {
    return res.status(503).json({ error: 'Treasurer account is not configured. Set TREASURER_PASSWORD in Hostinger Environment.' });
  }
  if (String(username || '').trim() !== TREASURER_USERNAME || String(password || '') !== TREASURER_PASSWORD) {
    return res.status(401).json({ error: 'Invalid Treasurer username or password.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { expiresAt: Date.now() + SESSION_TTL_MS, role: 'treasurer' });
  return res.json({ token, role: 'treasurer' });
});


/* =========================================================
   ADMIN LOGOUT
   ========================================================= */

app.post(
  '/api/admin/logout',
  requireAdmin,
  (req, res) => {

    const header =
      req.headers.authorization || '';

    const token =
      header.startsWith('Bearer ')
        ? header.slice(7)
        : null;

    if (token) {
      sessions.delete(token);
    }

    res.json({
      ok: true
    });

  }
);


/* =========================================================
   IMAGE UPLOAD
   SUPABASE STORAGE
   ========================================================= */

const upload =
  multer({

    storage:
      multer.memoryStorage(),

    limits: {
      fileSize:
        5 * 1024 * 1024
    },

    fileFilter:
      (req, file, cb) => {

        const allowedTypes = [
          'image/jpeg',
          'image/png',
          'image/webp',
          'image/gif'
        ];

        if (
          allowedTypes.includes(
            file.mimetype
          )
        ) {

          cb(null, true);

        } else {

          cb(
            new Error(
              'Only JPG, PNG, WEBP and GIF images are allowed'
            )
          );

        }

      }

  });


/* =========================================================
   UPLOAD API
   ========================================================= */

app.post(
  '/api/upload',
  requireAdmin,
  upload.single('file'),
  async (req, res) => {

    let uploadedFileName =
      null;

    try {

      if (!req.file) {

        return res.status(400).json({
          error:
            'No file uploaded'
        });

      }


      /*
       * Get extension
       */

      let ext =
        path.extname(
          req.file.originalname
        )
        .replace(
          '.',
          ''
        )
        .toLowerCase();

      if (!ext) {

        ext =
          req.file.mimetype
            .split('/')
            .pop() || 'jpg';

      }


      /*
       * Safe unique file name
       */

      uploadedFileName =
        `gallery/${Date.now()}-${crypto.randomUUID()}.${ext}`;


      /*
       * Upload to Supabase
       */

      /*
       * Upload to the dedicated Supabase Storage bucket.
       * If the bucket is missing, create it once and retry.
       * This requires SUPABASE_SERVICE_ROLE_KEY on the backend.
       */
      const bucketName = 'gallery';
      const uploadOptions = {
        contentType: req.file.mimetype,
        cacheControl: '3600',
        upsert: false
      };

      let uploadResponse = await supabase.storage
        .from(bucketName)
        .upload(uploadedFileName, req.file.buffer, uploadOptions);

      if (uploadResponse.error && /bucket not found|not found/i.test(uploadResponse.error.message || '')) {
        const createResponse = await supabase.storage.createBucket(bucketName, {
          public: true,
          fileSizeLimit: 5 * 1024 * 1024,
          allowedMimeTypes: ['image/jpeg', 'image/png', 'image/webp', 'image/gif']
        });

        // Ignore an already-existing bucket response; report other setup errors.
        if (createResponse.error && !/already exists|duplicate/i.test(createResponse.error.message || '')) {
          console.error('Supabase bucket creation error:', createResponse.error);
          return res.status(500).json({
            error: 'Supabase Storage bucket setup failed',
            details: createResponse.error.message
          });
        }

        uploadResponse = await supabase.storage
          .from(bucketName)
          .upload(uploadedFileName, req.file.buffer, uploadOptions);
      }

      if (uploadResponse.error) {
        console.error('Supabase upload error:', uploadResponse.error);
        const message = uploadResponse.error.message || 'Unknown Supabase Storage error';
        const likelySetupIssue = /permission|unauthorized|forbidden|invalid.*key|jwt/i.test(message);
        return res.status(500).json({
          error: 'Image upload failed',
          details: message,
          hint: likelySetupIssue
            ? 'Hostinger environment variables में SUPABASE_URL और SUPABASE_SERVICE_ROLE_KEY जाँचें।'
            : 'Supabase Dashboard → Storage में gallery bucket और उसकी settings जाँचें।'
        });
      }


      /*
       * Generate public URL
       */

      const {
        data: publicUrlData
      } =
        supabase.storage
          .from('gallery')
          .getPublicUrl(
            uploadedFileName
          );


      const imageUrl =
        publicUrlData &&
        publicUrlData.publicUrl
          ? publicUrlData.publicUrl
          : null;


      if (!imageUrl) {

        /*
         * Cleanup if URL was not generated
         */

        await supabase.storage
          .from('gallery')
          .remove([
            uploadedFileName
          ]);

        return res.status(500).json({
          error:
            'Could not generate image URL'
        });

      }


      /*
       * Return URL to Admin Panel
       */

      return res.json({

        ok: true,

        url:
          imageUrl,

        image:
          imageUrl,

        path:
          uploadedFileName

      });


    } catch (error) {

      console.error(
        'POST /api/upload:',
        error
      );


      /*
       * Cleanup uploaded file
       * if something failed afterwards
       */

      if (uploadedFileName) {

        try {

          await supabase.storage
            .from('gallery')
            .remove([
              uploadedFileName
            ]);

        } catch (
          cleanupError
        ) {

          console.error(
            'Upload cleanup error:',
            cleanupError
          );

        }

      }


      return res.status(500).json({
        error:
          error.message ||
          'Upload failed'
      });

    }

  }
);



/* =========================================================
   PRIVATE-ADMIN PDF UPLOADS FOR COMMUNITY CONTENT
   Dedicated bucket keeps PDF rules separate from image uploads.
   ========================================================= */
const pdfUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const isPdf = file.mimetype === 'application/pdf' && /\.pdf$/i.test(file.originalname || '');
    if (!isPdf) return cb(new Error('Only PDF documents are allowed.'));
    cb(null, true);
  }
});

app.post('/api/upload-document', requireAdmin, pdfUpload.single('file'), async (req, res) => {
  let uploadedPath = null;
  try {
    if (!req.file) return res.status(400).json({ error: 'No PDF document uploaded.' });
    const bucketName = 'resource-documents';
    uploadedPath = `community/${Date.now()}-${crypto.randomUUID()}.pdf`;
    const uploadOptions = { contentType: 'application/pdf', cacheControl: '3600', upsert: false };
    let result = await supabase.storage.from(bucketName).upload(uploadedPath, req.file.buffer, uploadOptions);
    if (result.error && /bucket not found|not found/i.test(result.error.message || '')) {
      const created = await supabase.storage.createBucket(bucketName, {
        public: true,
        fileSizeLimit: 15 * 1024 * 1024,
        allowedMimeTypes: ['application/pdf']
      });
      if (created.error && !/already exists|duplicate/i.test(created.error.message || '')) {
        console.error('PDF bucket creation error:', created.error);
        return res.status(500).json({ error: 'PDF Storage bucket setup failed', details: created.error.message });
      }
      result = await supabase.storage.from(bucketName).upload(uploadedPath, req.file.buffer, uploadOptions);
    }
    if (result.error) {
      console.error('PDF upload error:', result.error);
      return res.status(500).json({ error: 'PDF upload failed', details: result.error.message, hint: 'Supabase Storage में resource-documents bucket की settings जाँचें।' });
    }
    const { data } = supabase.storage.from(bucketName).getPublicUrl(uploadedPath);
    const url = data?.publicUrl || '';
    if (!url) {
      await supabase.storage.from(bucketName).remove([uploadedPath]);
      return res.status(500).json({ error: 'Could not generate PDF URL.' });
    }
    return res.json({ ok: true, url, path: uploadedPath, name: req.file.originalname, type: 'application/pdf' });
  } catch (error) {
    if (uploadedPath) {
      try { await supabase.storage.from('resource-documents').remove([uploadedPath]); } catch (cleanupError) { console.error('PDF cleanup error:', cleanupError); }
    }
    console.error('POST /api/upload-document:', error);
    return res.status(500).json({ error: error.message || 'PDF upload failed.' });
  }
});

/* =========================================================
   GENERIC CRUD ROUTES
   ========================================================= */

function crudRoutes(name) {


  /* -------------------------------------------------------
     PUBLIC READ
     ------------------------------------------------------- */

  app.get(
    `/api/${name}`,
    async (req, res) => {

      try {

        let items = await readCollection(name);


        /*
         * Gallery compatibility:
         *
         * Old records may contain:
         * image
         * imageUrl
         * url
         * photo
         *
         * Normalize everything to image.
         */

        if (
          name === 'gallery'
        ) {

          items =
            items.map(
              item => {

                const image =
                  item.image ||
                  item.imageUrl ||
                  item.url ||
                  item.photo ||
                  '';

                return {
                  ...item,
                  image
                };

              }
            );

        }


        res.json(items);

      } catch (error) {

        console.error(
          `GET /api/${name}`,
          error
        );

        res.status(500).json({
          error:
            'Database error'
        });

      }

    }
  );


  /* -------------------------------------------------------
     ADMIN CREATE
     ------------------------------------------------------- */

  app.post(
    `/api/${name}`,
    publicFormLimiter,
    requireAdmin,
    async (req, res) => {

      try {

        const db =
          await readDB();


        if (
          !Array.isArray(
            db[name]
          )
        ) {

          db[name] = [];

        }


        let body =
          {
            ...(req.body || {})
          };


        /*
         * Gallery image normalization
         */

        if (
          name === 'gallery'
        ) {

          const image =
            body.image ||
            body.imageUrl ||
            body.url ||
            body.photo ||
            '';

          body.image =
            image;

        }


        const item = {

          ...body,

          id: nextId(db[name])

        };


        db[name].push(
          item
        );


        await writeDB(db);


        res.status(201).json(
          item
        );


      } catch (error) {

        console.error(
          `POST /api/${name}`,
          error
        );

        res.status(500).json({
          error:
            'Database error'
        });

      }

    }
  );


  /* -------------------------------------------------------
     ADMIN UPDATE
     ------------------------------------------------------- */

  app.put(
    `/api/${name}/:id`,
    requireAdmin,
    async (req, res) => {

      try {

        const db =
          await readDB();

        const id =
          Number(
            req.params.id
          );


        if (
          !Array.isArray(
            db[name]
          )
        ) {

          db[name] = [];

        }


        const idx =
          db[name].findIndex(
            item =>
              Number(
                item.id
              ) === id
          );


        if (idx === -1) {

          return res.status(404)
            .json({
              error:
                'Not found'
            });

        }


        let body =
          {
            ...(req.body || {})
          };


        /*
         * Gallery normalization
         */

        if (
          name === 'gallery'
        ) {

          const image =
            body.image ||
            body.imageUrl ||
            body.url ||
            body.photo ||
            db[name][idx].image ||
            '';

          body.image =
            image;

        }


        db[name][idx] = {

          ...db[name][idx],

          ...body,

          id

        };


        await writeDB(db);


        res.json(
          db[name][idx]
        );


      } catch (error) {

        console.error(
          `PUT /api/${name}`,
          error
        );

        res.status(500).json({
          error:
            'Database error'
        });

      }

    }
  );


  /* -------------------------------------------------------
     ADMIN DELETE
     ------------------------------------------------------- */

  app.delete(
    `/api/${name}/:id`,
    requireAdmin,
    async (req, res) => {

      try {

        const db =
          await readDB();

        const id =
          Number(
            req.params.id
          );


        if (
          !Array.isArray(
            db[name]
          )
        ) {

          db[name] = [];

        }


        const existing =
          db[name].find(
            item =>
              Number(
                item.id
              ) === id
          );


        /*
         * If Gallery item has a Supabase
         * image path, delete image too.
         */

        if (
          name === 'gallery' &&
          existing
        ) {

          try {

            const imagePath =
              existing.path ||
              extractSupabaseGalleryPath(
                existing.image ||
                existing.imageUrl ||
                existing.url ||
                existing.photo ||
                ''
              );


            if (imagePath) {

              await supabase
                .storage
                .from('gallery')
                .remove([
                  imagePath
                ]);

            }

          } catch (
            storageError
          ) {

            console.error(
              'Gallery storage delete error:',
              storageError
            );

          }

        }


        db[name] =
          db[name].filter(
            item =>
              Number(
                item.id
              ) !== id
          );


        await writeDB(db);


        res.json({
          ok: true
        });


      } catch (error) {

        console.error(
          `DELETE /api/${name}`,
          error
        );

        res.status(500).json({
          error:
            'Database error'
        });

      }

    }
  );

}


/* =========================================================
   SUPABASE GALLERY PATH HELPER
   ========================================================= */

function extractSupabaseGalleryPath(
  url
) {

  if (
    !url ||
    typeof url !== 'string'
  ) {

    return null;

  }


  try {

    const marker =
      '/storage/v1/object/public/gallery/';


    const index =
      url.indexOf(marker);


    if (
      index === -1
    ) {

      return null;

    }


    return decodeURIComponent(
      url.slice(
        index +
        marker.length
      )
    );

  } catch (error) {

    return null;

  }

}


/* =========================================================
   ADMIN COLLECTIONS
   ========================================================= */

[
  'programs',
  'events',
  'gallery',
  'documents',
  'donors',
  'impactLocations', 'missions', 'impactStories', 'communityEvents', 'knowledgeLibrary'

].forEach(
  crudRoutes
);

// Certificate records are private to admins. Public visitors can only verify one ID.
app.get('/api/certificates', requireAdmin, async (req, res) => {
  try { const records = await readCollection('certificates'); res.set('Cache-Control', 'no-store'); res.json(records); }
  catch (e) { console.error('GET /api/certificates', e); res.status(500).json({error:'Database error'}); }
});
app.post('/api/certificates', requireAdmin, async (req, res) => {
  try { const db = await readDB(); db.certificates = Array.isArray(db.certificates) ? db.certificates : [];
    const body = req.body || {}; const applicationId = Number(body.applicationId);
    if (!Number.isSafeInteger(applicationId) || applicationId < 1) return res.status(400).json({error:'Valid applicationId required.'});
    const appRow = await pool.query('SELECT data FROM internships WHERE id=$1 LIMIT 1',[applicationId]);
    const appData = appRow.rows[0]?.data || {}; const attendance = appData.attendance || {};
    const presentDays = Array.isArray(attendance.days) ? attendance.days.filter(d => String(d.status||'').toLowerCase()==='present').length : Number(attendance.presentDays||0);
    const approvedProjects = await pool.query(`SELECT COUNT(*)::int AS total FROM project_submissions WHERE (data->>'applicationId')=$1 AND lower(COALESCE(data->>'status','submitted'))='approved'`,[String(applicationId)]);
    const projectApproved = Number(approvedProjects.rows[0]?.total||0)>0;
    if (presentDays !== 21 || attendance.approved !== true || !projectApproved) return res.status(409).json({error:`Certificate locked: attendance ${presentDays}/21, attendance approval ${attendance.approved===true?'approved':'pending'}, approved project ${projectApproved?'yes':'no'}.`});
    const item = {...body, id: nextId(db.certificates)}; db.certificates.push(item); await writeDB(db); res.status(201).json(item);
  } catch(e) { console.error('POST /api/certificates',e); res.status(500).json({error:'Database error'}); }
});
app.put('/api/certificates/:id', requireAdmin, async (req, res) => {
  try { const db=await readDB(); db.certificates=Array.isArray(db.certificates)?db.certificates:[]; const id=Number(req.params.id); const i=db.certificates.findIndex(x=>Number(x.id)===id); if(i<0)return res.status(404).json({error:'Not found'}); const body=req.body||{}; const applicationId=Number(body.applicationId||db.certificates[i].applicationId); const appRow=await pool.query('SELECT data FROM internships WHERE id=$1 LIMIT 1',[applicationId]); const appData=appRow.rows[0]?.data||{}; const attendance=appData.attendance||{}; const presentDays=Array.isArray(attendance.days)?attendance.days.filter(d=>String(d.status||'').toLowerCase()==='present').length:Number(attendance.presentDays||0); const approvedProjects=await pool.query(`SELECT COUNT(*)::int AS total FROM project_submissions WHERE (data->>'applicationId')=$1 AND lower(COALESCE(data->>'status','submitted'))='approved'`,[String(applicationId)]); const projectApproved=Number(approvedProjects.rows[0]?.total||0)>0; if(presentDays!==21||attendance.approved!==true||!projectApproved)return res.status(409).json({error:`Certificate locked: attendance ${presentDays}/21, attendance approval ${attendance.approved===true?'approved':'pending'}, approved project ${projectApproved?'yes':'no'}.`}); db.certificates[i]={...db.certificates[i],...body,id}; await writeDB(db); res.json(db.certificates[i]);
  } catch(e) { console.error('PUT /api/certificates',e); res.status(500).json({error:'Database error'}); }
});
app.delete('/api/certificates/:id', requireAdmin, async (req, res) => {
  try { const db=await readDB(); db.certificates=Array.isArray(db.certificates)?db.certificates:[]; const id=Number(req.params.id); const before=db.certificates.length; db.certificates=db.certificates.filter(x=>Number(x.id)!==id); if(before===db.certificates.length)return res.status(404).json({error:'Not found'}); await writeDB(db); res.json({ok:true}); }
  catch(e) { console.error('DELETE /api/certificates',e); res.status(500).json({error:'Database error'}); }
});

// Public, read-only certificate verification page for QR scans.
app.get('/certificate-verification/:certificateId', (req, res) => {
  const certificateId = String(req.params.certificateId || '').trim().slice(0, 100);
  res.set('Cache-Control', 'no-store');
  res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Certificate Verification | Nisha Seva Foundation</title><style>
  *{box-sizing:border-box}body{margin:0;padding:22px;background:#f2f5f8;color:#1c2b3a;font-family:Arial,sans-serif}.card{max-width:900px;margin:24px auto;background:#fff;border:1px solid #dce5ec;border-radius:18px;padding:26px;box-shadow:0 12px 35px #102a4312}.brand{text-align:center;color:#155b47;border-bottom:2px solid #e5bd63;padding-bottom:16px}.brand h1{font-size:22px;margin:0}.brand p{color:#64748b;margin:7px 0 0}.valid{display:inline-block;background:#e3f6eb;color:#11633f;padding:7px 12px;border-radius:20px;font-weight:700;margin:18px 0}.invalid{background:#fde8e8;color:#a3222b}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.field{padding:12px;background:#f7f9fb;border:1px solid #e7edf2;border-radius:10px}.field small{display:block;color:#718096;margin-bottom:5px}.field strong{overflow-wrap:anywhere}.section{margin-top:22px}.section h2{font-size:17px;color:#173e62;border-bottom:1px solid #e6edf2;padding-bottom:8px}table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:9px;border-bottom:1px solid #e8edf1;text-align:left}th{background:#f4f7fa;color:#526477}.present{color:#08764f;font-weight:700}.absent{color:#b42332;font-weight:700}.foot{text-align:center;color:#748295;font-size:12px;margin-top:22px}@media(max-width:600px){body{padding:8px}.card{padding:16px;margin:8px auto}.grid{grid-template-columns:1fr}table{font-size:12px}}
  </style></head><body><main class="card"><header class="brand"><h1>NISHA SEVA FOUNDATION</h1><p>Official Internship Certificate Verification</p></header><div id="result">Verifying certificate…</div><p class="foot">This is an online verification record. If any detail appears incorrect, contact the issuing institute.</p></main><script>
  const id=${JSON.stringify(certificateId)};
  const root=document.getElementById('result');
  const addField=(grid,label,value)=>{const d=document.createElement('div');d.className='field';const s=document.createElement('small');s.textContent=label;const b=document.createElement('strong');b.textContent=value||'—';d.append(s,b);grid.append(d);};
  (async()=>{try{const r=await fetch('/api/certificate-verify/'+encodeURIComponent(id),{cache:'no-store'});const j=await r.json();if(!j.valid){root.textContent=j.message||'Certificate not valid.';return;}const c=j.certificate||{};const badge=document.createElement('div');badge.className='valid';badge.textContent='✓ VALID CERTIFICATE';root.append(badge);const grid=document.createElement('div');grid.className='grid';root.append(grid);
  if(c.photo){const photo=document.createElement('img');photo.src=c.photo;photo.alt='Student Photo';photo.loading='lazy';photo.referrerPolicy='no-referrer';photo.style.cssText='display:block;width:112px;height:140px;object-fit:cover;border:2px solid #d5ad52;border-radius:12px;margin:14px auto';photo.onerror=()=>photo.remove();root.insertBefore(photo,grid);}
  [['Certificate No.',c.certificateId],['Student Name',c.name],['Parent Name',c.fatherName],['College / Institute',c.college],['University',c.university],['Course',c.course],['Semester',c.semester],['Roll / Enrollment No.',c.rollNumber],['Academic Year',c.academicYear],['Internship Organization',c.internshipOrganization],['Internship Period',(c.internshipStartDate||'—')+' to '+(c.internshipEndDate||'—')],['Issue Date',c.issueDate],['Verified Hours',String(c.hoursCompleted||0)],['Attendance',String(c.attendance?.presentDays||0)+' / '+String(c.attendance?.totalDays||0)+' days ('+String(c.attendance?.percentage||0)+'%)'],['Approved Project',c.projectApproved?'Yes':'No']].forEach(x=>addField(grid,x[0],String(x[1]||'')));
  const sec=document.createElement('section');sec.className='section';const h=document.createElement('h2');h.textContent='Day-wise Attendance Record';sec.append(h);const table=document.createElement('table');const thead=document.createElement('thead');thead.innerHTML='<tr><th>Day</th><th>Date</th><th>Status</th></tr>';table.append(thead);const tb=document.createElement('tbody');(Array.isArray(c.attendance?.days)?c.attendance.days:[]).forEach(d=>{const tr=document.createElement('tr');[String(d.day||''),String(d.date||'—'),String(d.status||'Absent')].forEach((v,i)=>{const td=document.createElement('td');td.textContent=v;if(i===2)td.className=String(d.status||'').toLowerCase()==='present'?'present':'absent';tr.append(td);});tb.append(tr);});table.append(tb);sec.append(table);root.append(sec);
  }catch(e){root.textContent='Verification service is temporarily unavailable. Please try again later.';}})();
  </script></body></html>`);
});

app.get('/api/certificate-verify/:certificateId', async (req, res) => {
  try {
    const wanted=String(req.params.certificateId||'').trim().toLowerCase();
    if(!wanted || wanted.length>100) return res.status(400).json({valid:false,error:'Invalid certificate ID'});
    const db=await readDB(); const list=Array.isArray(db.certificates)?db.certificates:[];
    const item=list.find(x=>String(x.certificateId||x.certificate_id||'').trim().toLowerCase()===wanted);
    if(!item || String(item.status||'active').toLowerCase()==='revoked') return res.json({valid:false,message:'Certificate not found or revoked'});
    const attendance = item.attendance && typeof item.attendance === 'object' ? item.attendance : {};
    const projects = Array.isArray(item.projects) ? item.projects : [];
    let certificatePhoto = nsfGetStudentPhoto(item);
    if (!certificatePhoto && Number.isSafeInteger(Number(item.applicationId)) && Number(item.applicationId) > 0) {
      await internshipTableReady;
      const sourceApp = await pool.query('SELECT data FROM internships WHERE id=$1 LIMIT 1', [Number(item.applicationId)]);
      certificatePhoto = nsfGetStudentPhoto(sourceApp.rows[0]?.data || {});
    }
    res.set('Cache-Control','no-store');
    res.json({valid:true,certificate:{
      photo:certificatePhoto,
      certificateId:item.certificateId||item.certificate_id,
      name:item.name||item.studentName||'',
      fatherName:item.fatherName||item.parentName||'',
      college:item.college||item.collegeName||'',
      university:item.university||'',
      course:item.course||item.program||'',
      semester:item.semester||'',
      rollNumber:item.rollNumber||'',
      academicYear:item.academicYear||'',
      internshipOrganization:item.internshipOrganization||'Nisha Seva Foundation',
      internshipStartDate:item.internshipStartDate||'',
      internshipEndDate:item.internshipEndDate||'',
      internshipDuration:item.internshipDuration||'',
      workDescription:item.workDescription||'',
      internshipId:item.internshipId||'',
      referenceNo:item.referenceNo||item.internshipId||'',
      issueDate:item.issueDate||item.issuedAt||'',
      attendance:{
        presentDays:Number(attendance.presentDays||0),
        totalDays:Number(attendance.totalDays||0),
        absentDays:Number(attendance.absentDays||0),
        percentage:Number(attendance.percentage||0),
        days:Array.isArray(attendance.days)?attendance.days.map((d,i)=>({
          day:Number(d.day||i+1),
          date:String(d.date||''),
          status:String(d.status||'absent').toLowerCase()==='present'?'Present':'Absent'
        })):[]
      },
      hoursCompleted:Number(item.hoursCompleted||item.internshipHours||0),
      projectWork:projects.some(p=>String(p.status||'').toLowerCase()==='approved')?'Yes':'No',
      projectApproved:projects.some(p=>String(p.status||'').toLowerCase()==='approved'),
      projectTitles:projects.map(p=>String(p.title||p.projectTitle||'')).filter(Boolean).slice(0,10),
      issuer:'Nisha Seva Foundation',
      status:'Valid'
    }});
  } catch(e) { console.error('GET /api/certificate-verify',e); res.status(500).json({valid:false,error:'Verification unavailable'}); }
});


/* =========================================================
   SUBMISSION TABLES
   ========================================================= */

const submissionTables = {

  volunteers:
    'volunteers',

  members:
    'members',

  contactMessages:
    'contact_messages',

  newsletter:
    'newsletter',

  internships:
    'internships'

};


// Admin list optimization: strip inline data URLs from summary-only responses.
function nsfStripInlinePayload(value) {
  if (Array.isArray(value)) return value.map(nsfStripInlinePayload);
  if (!value || typeof value !== 'object') {
    if (typeof value === 'string' && /^data:[^;,]+;base64,/i.test(value)) return undefined;
    return value;
  }
  const out = {};
  for (const [key, child] of Object.entries(value)) {
    if (typeof child === 'string' && /^data:[^;,]+;base64,/i.test(child)) {
      // Keep metadata around uploaded files while omitting the large payload.
      if (key === 'data') continue;
      out[key] = '[file payload omitted from list view]';
      continue;
    }
    const clean = nsfStripInlinePayload(child);
    if (clean !== undefined) out[key] = clean;
  }
  return out;
}

const nsfAdminListCache = new Map();
const nsfAdminListInflight = new Map();
let nsfAdminListGeneration = 0;
const NSF_ADMIN_LIST_CACHE_TTL_MS = 15000;

function nsfGetCachedList(key) {
  const entry = nsfAdminListCache.get(key);
  if (!entry || Date.now() - entry.at > NSF_ADMIN_LIST_CACHE_TTL_MS) {
    nsfAdminListCache.delete(key);
    return null;
  }
  return entry.value;
}
function nsfSetCachedList(key, value) {
  nsfAdminListCache.set(key, { at: Date.now(), value });
  if (nsfAdminListCache.size > 30) nsfAdminListCache.delete(nsfAdminListCache.keys().next().value);
}
async function nsfLoadCachedList(key, loader) {
  const cached = nsfGetCachedList(key);
  if (cached !== null) return { value: cached, cache: 'HIT' };
  const pending = nsfAdminListInflight.get(key);
  if (pending) return { value: await pending, cache: 'WAIT' };
  const generation = nsfAdminListGeneration;
  const request = Promise.resolve().then(loader);
  nsfAdminListInflight.set(key, request);
  try {
    const value = await request;
    if (generation === nsfAdminListGeneration) nsfSetCachedList(key, value);
    return { value, cache: 'MISS' };
  } finally {
    if (nsfAdminListInflight.get(key) === request) nsfAdminListInflight.delete(key);
  }
}
function nsfClearAdminListCache() {
  nsfAdminListGeneration++;
  nsfAdminListCache.clear();
  nsfAdminListInflight.clear();
}

/* =========================================================
   SUBMISSION ROUTES
   ========================================================= */

function submissionRoutes(
  name
) {

  const table =
    submissionTables[name];


  if (!table) {

    console.error(
      `Unknown submission collection: ${name}`
    );

    return;

  }


  /* -------------------------------------------------------
     PUBLIC FORM SUBMISSION
     ------------------------------------------------------- */

  app.post(
    `/api/${name}`,
    publicFormLimiter,
    async (req, res) => {

      try {

        if (name === 'internships') {
          await internshipTableReady;
        }

        const submissionData =
          {
            ...(req.body || {})
          };


        /*
         * Volunteer applications
         * always start as pending.
         */

        if (
          name === 'volunteers'
        ) {

          submissionData.status =
            'pending';

          submissionData.volunteerId =
            null;

          submissionData.verificationCode =
            null;

          submissionData.verificationUrl =
            null;

          submissionData.approvedAt =
            null;

          submissionData.issuedAt =
            null;

          submissionData.revokedAt =
            null;

          submissionData.rejectedAt =
            null;

        }

        /*
         * Student Internship applications
         * always start as pending.
         * System-controlled approval fields are
         * overwritten here so a public form cannot
         * self-approve or issue an Internship ID.
         */
        if (
          name === 'internships'
        ) {

          submissionData.status =
            'pending';

          // Permanent public token is created for EVERY application at submission.
          // It is random, non-sequential and contains no personal information.
          submissionData.publicProfileId = crypto.randomBytes(18).toString('hex');
          submissionData.internshipId = null;

          submissionData.approvedAt =
            null;

          submissionData.issuedAt =
            null;

          submissionData.revokedAt =
            null;

          submissionData.rejectedAt =
            null;

        }


        let result;

        if (name === 'internships') {
          // One internship application per normalized email OR mobile number.
          // Transaction-level advisory lock prevents concurrent duplicate submissions.
          const email = String(submissionData.email || submissionData.gmail || '').trim().toLowerCase();
          const rawPhone = String(submissionData.mobile || submissionData.phone || submissionData.mobileNumber || '').trim();
          let phone = rawPhone.replace(/\D/g, '');
          if (phone.length === 12 && phone.startsWith('91')) phone = phone.slice(2);
          if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: 'कृपया सही Email दर्ज करें।' });
          }
          if (!/^\d{10}$/.test(phone)) {
            return res.status(400).json({ error: 'कृपया 10 अंकों का सही मोबाइल नंबर दर्ज करें।' });
          }
          submissionData.email = email;
          submissionData.mobile = phone;
          const client = await pool.connect();
          try {
            await client.query('BEGIN');
            await client.query('SELECT pg_advisory_xact_lock($1)', [847261904]);
            // The predicates below intentionally match the existing expression
            // indexes: idx_internships_email_normalized and idx_internships_mobile.
            // Compare both 10-digit and legacy +91-prefixed phone forms.
            const duplicate = await client.query(
              `SELECT id,
                      lower(trim(coalesce(data->>'email', data->>'gmail', ''))) AS email,
                      regexp_replace(
                        coalesce(data->>'mobile', data->>'phone', data->>'mobileNumber', ''),
                        '[^0-9]', '', 'g'
                      ) AS phone_digits
                 FROM internships
                WHERE lower(trim(coalesce(data->>'email', data->>'gmail', ''))) = $1
                   OR regexp_replace(
                        coalesce(data->>'mobile', data->>'phone', data->>'mobileNumber', ''),
                        '[^0-9]', '', 'g'
                      ) IN ($2, '91' || $2)
                LIMIT 1`,
              [email, phone]
            );
            if (duplicate.rows.length) {
              const old = duplicate.rows[0];
              await client.query('ROLLBACK');
              if (String(old.email || '').toLowerCase() === email) {
                return res.status(409).json({ error: 'इस Email से Internship Form पहले ही जमा हो चुका है। एक Email से केवल एक आवेदन स्वीकार होगा।', code: 'DUPLICATE_EMAIL' });
              }
              if (String(old.phone_digits || '').replace(/^91(?=\d{10}$)/, '') === phone) {
                return res.status(409).json({ error: 'इस मोबाइल नंबर से Internship Form पहले ही जमा हो चुका है। एक मोबाइल नंबर से केवल एक आवेदन स्वीकार होगा।', code: 'DUPLICATE_PHONE' });
              }
              return res.status(409).json({ error: 'इस Email या मोबाइल नंबर से आवेदन पहले ही जमा हो चुका है।', code: 'DUPLICATE_INTERNSHIP' });
            }
            result = await client.query(
              `INSERT INTO internships (data) VALUES ($1::jsonb) RETURNING id, data, created_at`,
              [JSON.stringify(submissionData)]
            );
            await client.query('COMMIT');
          } catch (internshipError) {
            try { await client.query('ROLLBACK'); } catch (_) {}
            throw internshipError;
          } finally {
            client.release();
          }
        } else if (name === 'volunteers') {
          // Normalize identifiers consistently so +91, spaces and hyphens
          // cannot be used to submit the same volunteer application again.
          const email = String(submissionData.email || submissionData.gmail || '')
            .trim().toLowerCase();
          const rawPhone = String(
            submissionData.phone || submissionData.mobile || submissionData.mobileNumber || ''
          ).trim();
          let phone = rawPhone.replace(/\D/g, '');
          if (phone.length === 12 && phone.startsWith('91')) phone = phone.slice(2);

          if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: 'कृपया सही Email/Gmail दर्ज करें।' });
          }
          if (!/^\d{10}$/.test(phone)) {
            return res.status(400).json({ error: 'कृपया 10 अंकों का सही मोबाइल नंबर दर्ज करें।' });
          }

          submissionData.email = email;
          submissionData.phone = phone;
          if (submissionData.photoUrl) {
            const photoMatch = /^data:image\/(?:jpeg|jpg|png|webp);base64,([A-Za-z0-9+/=]+)$/i.exec(String(submissionData.photoUrl));
            if (!photoMatch) return res.status(400).json({ error: 'Volunteer photo का format सही नहीं है। JPG/JPEG/PNG/WEBP इस्तेमाल करें।' });
            const photoBytes = Math.floor(photoMatch[1].length * 3 / 4) - (photoMatch[1].endsWith('==') ? 2 : photoMatch[1].endsWith('=') ? 1 : 0);
            if (photoBytes > 100 * 1024) return res.status(413).json({ error: 'Volunteer photo अधिकतम 100 KB की होनी चाहिए।' });
          }

          // A transaction-level advisory lock serializes volunteer submissions;
          // this closes the race where two identical requests arrive together.
          const client = await pool.connect();
          try {
            await client.query('BEGIN');
            await client.query('SELECT pg_advisory_xact_lock($1)', [847261903]);

            // Keep the SQL expressions identical to the matching expression indexes.
            // Legacy +91-prefixed values are checked alongside normalized 10-digit values.
            const duplicate = await client.query(
              `SELECT id,
                      lower(trim(coalesce(data->>'email', data->>'gmail', ''))) AS email,
                      regexp_replace(
                        coalesce(data->>'phone', data->>'mobile', data->>'mobileNumber', ''),
                        '[^0-9]', '', 'g'
                      ) AS phone_digits
                 FROM volunteers
                WHERE lower(trim(coalesce(data->>'email', data->>'gmail', ''))) = $1
                   OR regexp_replace(
                        coalesce(data->>'phone', data->>'mobile', data->>'mobileNumber', ''),
                        '[^0-9]', '', 'g'
                      ) IN ($2, '91' || $2)
                LIMIT 1`,
              [email, phone]
            );

            if (duplicate.rows.length) {
              const oldEmail = String(duplicate.rows[0].email || '').trim().toLowerCase();
              const oldPhone = String(duplicate.rows[0].phone_digits || '').replace(/^91(?=\d{10}$)/, '');
              await client.query('ROLLBACK');
              if (oldEmail === email) {
                return res.status(409).json({ error: 'इस Email/Gmail से Volunteer Form पहले ही जमा हो चुका है। एक Email से केवल एक आवेदन स्वीकार होगा।', code: 'DUPLICATE_EMAIL' });
              }
              if (oldPhone === phone) {
                return res.status(409).json({ error: 'इस मोबाइल नंबर से Volunteer Form पहले ही जमा हो चुका है। एक मोबाइल नंबर से केवल एक आवेदन स्वीकार होगा।', code: 'DUPLICATE_PHONE' });
              }
              return res.status(409).json({ error: 'इस Email या मोबाइल नंबर से आवेदन पहले ही जमा हो चुका है।', code: 'DUPLICATE_VOLUNTEER' });
            }

            result = await client.query(
              `INSERT INTO volunteers (data) VALUES ($1::jsonb)
               RETURNING id, data, created_at`,
              [JSON.stringify(submissionData)]
            );
            await client.query('COMMIT');
          } catch (volunteerError) {
            try { await client.query('ROLLBACK'); } catch (_) {}
            throw volunteerError;
          } finally {
            client.release();
          }
        } else {
          result = await pool.query(
            `INSERT INTO ${table} (data)
             VALUES ($1::jsonb)
             RETURNING id, data, created_at`,
            [JSON.stringify(submissionData)]
          );
        }


        nsfClearAdminListCache();
        const row = result.rows[0];
        let referenceNo = null;
        if (name === 'internships') {
          referenceNo = `NSF-INT-${row.id}`;
          const publicProfileUrl = `${(process.env.PUBLIC_STUDENT_VERIFY_BASE || 'https://nishasevafoundation.org/student-verification.html').replace(/\/$/, '')}?id=${encodeURIComponent((row.data || {}).publicProfileId)}`;
          const updatedData = { ...(row.data || {}), referenceNo, applicationReference: referenceNo, studentId: `NSF-STU-${String(row.id).padStart(6,'0')}`, publicProfileUrl };
          await pool.query('UPDATE internships SET data=$1::jsonb WHERE id=$2', [JSON.stringify(updatedData), row.id]);
        }

        const savedRow = name === 'internships' ? (await pool.query('SELECT data FROM internships WHERE id=$1', [row.id])).rows[0]?.data || {} : {};
        res.status(201).json({
          ok: true,
          id: row.id,
          referenceNo,
          publicProfileId: savedRow.publicProfileId || null,
          publicProfileUrl: savedRow.publicProfileUrl || null,
          studentId: savedRow.studentId || null
        });


      } catch (error) {

        console.error(
          `POST /api/${name}`,
          error
        );

        res.status(500).json({

          error:
            'Database error'

        });

      }

    }
  );


  /* -------------------------------------------------------
     ADMIN READ
     ------------------------------------------------------- */

  app.get(
    `/api/${name}`,
    requireAdmin,
    async (req, res) => {

      try {

        if (name === 'internships') {
          await internshipTableReady;
        }

        const summaryOnly = req.query.summary === '1';
        // Keep the existing array response for Admin Panel compatibility, while
        // bounding the two high-volume internship list modes. offset is optional
        // and can be used by a future UI pager without changing this response shape.
        const boundedInternshipList = name === 'internships';
        const requestedLimit = Number.parseInt(req.query.limit || '1000', 10);
        const listLimit = boundedInternshipList
          ? Math.min(2000, Math.max(1, Number.isFinite(requestedLimit) ? requestedLimit : 1000))
          : null;
        const requestedOffset = Number.parseInt(req.query.offset || '0', 10);
        const listOffset = boundedInternshipList
          ? Math.min(1000000, Math.max(0, Number.isFinite(requestedOffset) ? requestedOffset : 0))
          : 0;
        const cacheKey = `admin-list:${name}:${summaryOnly ? 'summary' : 'full'}:${listLimit || 'all'}:${listOffset}`;

        const loadRows = async () => {
          // V8 summary reads use compact sidecar tables maintained by PostgreSQL
          // triggers. This avoids repeatedly detoasting large JSONB records that
          // contain base64 photos/signatures. Full mode remains available and bounded.
          const queryStarted = process.hrtime.bigint();
          let result;
          if (summaryOnly && name === 'internships') {
            result = await pool.query(
              `SELECT id, created_at, data
               FROM nsf_internship_list_cache
               ORDER BY created_at DESC, id DESC
               LIMIT $1 OFFSET $2`,
              [listLimit, listOffset]
            );
          } else {
            const pagingSql = boundedInternshipList ? ' LIMIT $1 OFFSET $2' : '';
            const sql = summaryOnly
              ? `SELECT id, created_at,
                   COALESCE((SELECT jsonb_object_agg(k, v)
                     FROM jsonb_each(data) AS e(k, v)
                     WHERE NOT (jsonb_typeof(v) = 'string'
                       AND (v #>> '{}') LIKE 'data:%;base64,%')), '{}'::jsonb) AS data
                 FROM ${table} ORDER BY created_at DESC${pagingSql}`
              : `SELECT id, data, created_at FROM ${table} ORDER BY created_at DESC${pagingSql}`;
            result = await pool.query(sql, boundedInternshipList ? [listLimit, listOffset] : []);
          }
          const queryMs = Number(process.hrtime.bigint() - queryStarted) / 1e6;
          const rows = result.rows.map(row => ({
            id: row.id,
            submittedAt: row.created_at,
            ...(summaryOnly ? nsfStripInlinePayload(row.data || {}) : (row.data || {}))
          }));
          return { rows, queryMs };
        };

        if (summaryOnly) {
          const loaded = await nsfLoadCachedList(cacheKey, loadRows);
          res.set('X-NSF-Cache', loaded.cache);
          res.set('X-NSF-DB-Query-Ms', loaded.cache === 'MISS' ? 'measured' : 'cached');
          if (boundedInternshipList) { res.set('X-NSF-Page-Limit', String(listLimit)); res.set('X-NSF-Page-Offset', String(listOffset)); }
          res.set('Cache-Control', 'private, no-store');
          return res.json(loaded.value.rows);
        }

        const loaded = await loadRows();
        res.set('X-NSF-DB-Query-Ms', loaded.queryMs.toFixed(1));
        if (boundedInternshipList) { res.set('X-NSF-Page-Limit', String(listLimit)); res.set('X-NSF-Page-Offset', String(listOffset)); }
        res.set('Cache-Control', 'private, no-store');
        return res.json(loaded.rows);


      } catch (error) {

        console.error(
          `GET /api/${name}`,
          error
        );

        res.status(500).json({

          error:
            'Database error'

        });

      }

    }
  );


  /* -------------------------------------------------------
     ADMIN DELETE
     ------------------------------------------------------- */

  app.delete(
    `/api/${name}/:id`,
    requireAdmin,
    async (req, res) => {

      try {

        if (name === 'internships') {
          await internshipTableReady;
        }

        const id =
          Number(
            req.params.id
          );


        if (
          !Number.isInteger(id)
        ) {

          return res.status(400)
            .json({

              error:
                'Invalid ID'

            });

        }


        await pool.query(

          `DELETE FROM ${table}
           WHERE id = $1`,

          [id]

        );
        nsfClearAdminListCache();

        res.json({
          ok: true
        });


      } catch (error) {

        console.error(
          `DELETE /api/${name}`,
          error
        );

        res.status(500).json({

          error:
            'Database error'

        });

      }

    }
  );

}


/* =========================================================
   REGISTER SUBMISSION ROUTES
   ========================================================= */

[
  'volunteers',
  'members',
  'contactMessages',
  'newsletter',
  'internships'
].forEach(
  submissionRoutes
);


// Return only the selected student's photo field. This keeps summary list responses
// lightweight while allowing Admin cards, ID cards and certificates to load the image.
function nsfGetStudentPhoto(data) {
  const d = data && typeof data === 'object' ? data : {};
  let value = d.studentPhoto || d.studentPhotoUrl || d.photoUrl || d.photoDataUrl ||
    d.passportPhoto || d.profilePhoto || d.profileImage || d.uploadedPhoto ||
    d.photo || d.imageUrl || d.image || d.picture || d.studentImage ||
    d.student_photo || d.student_photo_url || d.profile_picture || null;
  if (value && typeof value === 'object') {
    value = value.dataUrl || value.dataURL || value.url || value.src ||
      value.preview || value.publicUrl || value.public_url || value.downloadUrl ||
      value.fileUrl || value.file_url || value.path || null;
  }
  if (typeof value !== 'string') return null;
  value = value.trim();
  if (/^data:image\/(?:png|jpeg|jpg|webp);base64,/i.test(value) || /^https:\/\//i.test(value)) return value;
  return null;
}

app.get('/api/internships/:id/photo', requireAdmin, async (req, res) => {
  try {
    await internshipTableReady;
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid application ID.' });
    const result = await pool.query('SELECT data FROM internships WHERE id=$1 LIMIT 1', [id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Application not found.' });
    const photo = nsfGetStudentPhoto(result.rows[0].data || {});
    res.set('Cache-Control', 'private, no-store');
    return res.json({ ok: true, photo });
  } catch (error) {
    console.error('GET /api/internships/:id/photo:', error);
    return res.status(500).json({ error: 'Student photo could not be loaded.' });
  }
});

// Public QR verification for every submitted internship application.
// Only deliberately selected basic fields are returned; no contact details or documents.
app.get('/api/student/verify/:publicId', publicFormLimiter, async (req, res) => {
  try {
    await internshipTableReady;
    const token = String(req.params.publicId || '');
    if (!/^[a-f0-9]{36}$/i.test(token)) return res.status(404).json({ error: 'Student profile not found.' });
    const result = await pool.query(
      `SELECT id, data, created_at FROM internships WHERE data->>'publicProfileId'=$1 LIMIT 1`, [token]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Student profile not found.' });
    const row=result.rows[0], d=row.data||{};
    // Accept the photo field aliases already used by the Admin Panel and forms.
    // Only image data URLs or HTTPS URLs are exposed on this public verification profile.
    let photoValue = nsfGetStudentPhoto(d);
    if (photoValue && typeof photoValue === 'object') {
      photoValue = photoValue.dataUrl || photoValue.url || photoValue.src ||
        photoValue.preview || photoValue.publicUrl || photoValue.downloadUrl || null;
    }
    const safePhoto = typeof photoValue === 'string' &&
      (/^data:image\/(?:png|jpeg|jpg|webp);base64,/i.test(photoValue) || /^https:\/\//i.test(photoValue))
      ? photoValue : null;
    const safe = {
      studentId: d.studentId || `NSF-STU-${String(row.id).padStart(6,'0')}`,
      applicationId: row.id,
      studentName: d.studentName || d.name || 'Student',
      photo: safePhoto,
      college: d.collegeName || d.educationCollege || null,
      university: d.university || null,
      course: d.className || d.program || 'Student Internship',
      yearSemester: d.yearSemester || null,
      programme: d.program || 'Student Internship',
      duration: d.duration || null,
      interests: Array.isArray(d.interests) ? d.interests : (d.interests ? [String(d.interests)] : []),
      internshipId: d.internshipId || null,
      applicationStatus: d.status || 'pending',
      submittedOn: d.applicationDate || row.created_at,
      verificationStatus: ['revoked','rejected'].includes(String(d.status||'').toLowerCase()) ? 'Not Valid' : 'Record Found'
    };
    res.set('Cache-Control','no-store');
    return res.json({ success:true, profile:safe });
  } catch (error) {
    console.error('STUDENT VERIFY ERROR:', error);
    return res.status(500).json({ error:'Student verification is temporarily unavailable.' });
  }
});

// Admin-only migration helper: issue a permanent public QR token to older applications.
app.post('/api/internships/:id/ensure-public-id', requireAdmin, async (req,res) => {
  try {
    await internshipTableReady;
    const id=Number(req.params.id);
    if(!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:'Invalid application ID.'});
    const found=await pool.query('SELECT data FROM internships WHERE id=$1 LIMIT 1',[id]);
    if(!found.rows.length) return res.status(404).json({error:'Application not found.'});
    const d=found.rows[0].data||{};
    if(!d.publicProfileId) d.publicProfileId=crypto.randomBytes(18).toString('hex');
    if(!d.studentId) d.studentId=`NSF-STU-${String(id).padStart(6,'0')}`;
    d.publicProfileUrl=`${(process.env.PUBLIC_STUDENT_VERIFY_BASE || 'https://nishasevafoundation.org/student-verification.html').replace(/\/$/, '')}?id=${encodeURIComponent(d.publicProfileId)}`;
    await pool.query('UPDATE internships SET data=$1::jsonb WHERE id=$2',[JSON.stringify(d),id]);
    return res.json({success:true,studentId:d.studentId,publicProfileId:d.publicProfileId,publicProfileUrl:d.publicProfileUrl,application:d});
  } catch(error) {
    console.error('ENSURE STUDENT QR ERROR:',error);
    return res.status(500).json({error:'Could not prepare student ID card.'});
  }
});


/* =========================================================
   SERIALIZED DATABASE SCHEMA INITIALIZATION
   Avoid opening many Supabase session-pool connections at startup.
   ========================================================= */
let schemaInitQueue = Promise.resolve();
function initializeTable(sql, label) {
  const operation = schemaInitQueue.then(() => pool.query(sql));
  // Keep the queue usable after an individual initialization fails;
  // the returned operation still rejects and startup reports the failure.
  schemaInitQueue = operation.then(() => undefined, () => undefined);
  return operation.catch((error) => {
    console.error(`${label} TABLE INIT ERROR:`, error.message || error);
    throw error;
  });
}

/* =========================================================
   STUDENT INTERNSHIP APPROVAL SYSTEM
   ========================================================= */

/*
 * Create the internships table automatically if it does not
 * already exist. The rest of this server stores submission
 * payloads in JSONB, so this follows the same pattern.
 */

/* =========================================================
   GENERAL SECRETARY WORKSPACE
   ========================================================= */
const secretaryTableReady = initializeTable(`
  CREATE TABLE IF NOT EXISTS nsf_secretary_records (
    id BIGSERIAL PRIMARY KEY,
    category VARCHAR(60) NOT NULL,
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(40) NOT NULL DEFAULT 'draft',
    created_by VARCHAR(80) NOT NULL DEFAULT 'secretary',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE INDEX IF NOT EXISTS nsf_secretary_records_category_idx ON nsf_secretary_records(category, created_at DESC);
`, 'SECRETARY');

const secretaryPrivateDir = path.join(__dirname, 'secretary-private-documents');
if (!fs.existsSync(secretaryPrivateDir)) fs.mkdirSync(secretaryPrivateDir, { recursive: true });

const secretaryDocumentUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, secretaryPrivateDir),
    filename: (req, file, cb) => cb(null, `nsf-secretary-${Date.now()}-${crypto.randomUUID()}${path.extname(file.originalname || '').toLowerCase()}`)
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = new Set(['application/pdf','image/jpeg','image/png','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document']);
    cb(allowed.has(file.mimetype) ? null : new Error('Only PDF, JPG, PNG, DOC and DOCX files are allowed.'), allowed.has(file.mimetype));
  }
});
const secretaryAllowedCategories = new Set(['meeting','meeting_notice','meeting_minutes','attendance','proposal','official_letter','program_report','annual_report','office_bearer','office_bearer_request','pending_task','president_report']);

app.get('/api/secretary/records', requireAdmin, async (req,res) => {
  try {
    await secretaryTableReady;
    const category=String(req.query.category||'').trim();
    const result=category
      ? await pool.query('SELECT id,category,data,status,created_by,created_at,updated_at FROM nsf_secretary_records WHERE category=$1 ORDER BY created_at DESC LIMIT 500',[category])
      : await pool.query('SELECT id,category,data,status,created_by,created_at,updated_at FROM nsf_secretary_records ORDER BY created_at DESC LIMIT 500');
    res.set('Cache-Control','no-store');
    return res.json(result.rows.map(r=>({id:r.id,category:r.category,...(r.data||{}),status:r.status,createdBy:r.created_by,createdAt:r.created_at,updatedAt:r.updated_at})));
  } catch(error) { console.error('SECRETARY RECORD LIST ERROR:',error); return res.status(500).json({error:'Secretariat records could not be loaded.'}); }
});

app.post('/api/secretary/records', requireAdmin, async (req,res) => {
  try {
    await secretaryTableReady;
    const body=req.body||{}, category=String(body.category||'').trim(), title=String(body.title||'').trim().slice(0,180), content=String(body.content||'').trim().slice(0,12000);
    const status=['draft','pending','in_progress','completed'].includes(String(body.status||''))?String(body.status):'draft';
    if(!secretaryAllowedCategories.has(category)||!title||!content) return res.status(400).json({error:'A valid category, title and description are required.'});
    const data={title,content,date:String(body.date||'').slice(0,10),location:String(body.location||'').trim().slice(0,220)};
    const result=await pool.query(`INSERT INTO nsf_secretary_records(category,data,status,created_by) VALUES($1,$2::jsonb,$3,$4) RETURNING id,category,data,status,created_at`,[category,JSON.stringify(data),status,req.userRole||'secretary']);
    const r=result.rows[0]; return res.status(201).json({id:r.id,category:r.category,...(r.data||{}),status:r.status,createdAt:r.created_at});
  } catch(error) { console.error('SECRETARY RECORD SAVE ERROR:',error); return res.status(500).json({error:'Secretariat record could not be saved.'}); }
});

app.post('/api/secretary/member-requests', requireAdmin, async (req,res) => {
  try {
    await secretaryTableReady;
    const body=req.body||{}, name=String(body.name||'').trim().slice(0,140), phone=String(body.phone||'').replace(/\D/g,'').slice(-10), email=String(body.email||'').trim().toLowerCase().slice(0,180);
    if(!name||!/^\d{10}$/.test(phone)) return res.status(400).json({error:'Member name and a 10-digit mobile number are required.'});
    if(email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:'Email address is invalid.'});
    const data={name,phone,email,address:String(body.address||'').trim().slice(0,300),reason:String(body.reason||'').trim().slice(0,3000)};
    const result=await pool.query(`INSERT INTO nsf_secretary_records(category,data,status,created_by) VALUES('member_add_request',$1::jsonb,'pending_approval','secretary') RETURNING id,created_at`,[JSON.stringify(data)]);
    return res.status(201).json({ok:true,id:result.rows[0].id,status:'pending_approval',createdAt:result.rows[0].created_at});
  } catch(error) { console.error('SECRETARY MEMBER REQUEST ERROR:',error); return res.status(500).json({error:'Membership request could not be saved.'}); }
});

// Only Admin/President can view and approve pending secretary member requests.
app.get('/api/secretary/member-requests', requireAdmin, async (req,res) => {
  try {
    if(req.userRole!=='admin') return res.status(403).json({error:'Only Admin/President can view this list.'});
    await secretaryTableReady;
    const result=await pool.query(`SELECT id,data,status,created_at FROM nsf_secretary_records WHERE category='member_add_request' ORDER BY created_at DESC LIMIT 300`);
    return res.json(result.rows.map(r=>({id:r.id,...(r.data||{}),status:r.status,createdAt:r.created_at})));
  } catch(error) { console.error('SECRETARY MEMBER REQUEST LIST ERROR:',error); return res.status(500).json({error:'Member requests could not be loaded.'}); }
});

// Final member activation is restricted to Admin/President.
app.post('/api/secretary/member-requests/:id/approve', requireAdmin, async (req,res) => {
  try {
    if(req.userRole!=='admin') return res.status(403).json({error:'Only Admin/President can grant final approval.'});
    await secretaryTableReady;
    const id=Number(req.params.id), found=await pool.query(`SELECT data,status FROM nsf_secretary_records WHERE id=$1 AND category='member_add_request'`,[id]);
    if(!found.rows.length) return res.status(404).json({error:'Membership request was not found.'});
    if(found.rows[0].status==='approved') return res.status(409).json({error:'This request has already been approved.'});
    const d=found.rows[0].data||{}, memberData={...d,status:'active',approvedBy:'admin',approvedAt:new Date().toISOString(),source:'secretary_request'};
    const member=await pool.query('INSERT INTO members(data) VALUES($1::jsonb) RETURNING id',[JSON.stringify(memberData)]);
    await pool.query(`UPDATE nsf_secretary_records SET status='approved',updated_at=NOW() WHERE id=$1`,[id]);
    return res.json({ok:true,memberId:member.rows[0].id});
  } catch(error) { console.error('SECRETARY MEMBER APPROVAL ERROR:',error); return res.status(500).json({error:'Membership request could not be approved.'}); }
});

app.post('/api/secretary/documents', requireAdmin, secretaryDocumentUpload.single('file'), async (req,res) => {
  try {
    await secretaryTableReady;
    if(!req.file) return res.status(400).json({error:'Please select a document.'});
    const title=String(req.body.title||req.file.originalname||'Document').trim().slice(0,180);
    const data={title,fileName:path.basename(req.file.originalname||'document'),storedName:path.basename(req.file.filename),size:req.file.size,mimeType:req.file.mimetype};
    const saved=await pool.query(`INSERT INTO nsf_secretary_records(category,data,status,created_by) VALUES('document',$1::jsonb,'uploaded',$2) RETURNING id`,[JSON.stringify(data),req.userRole||'secretary']);
    return res.status(201).json({ok:true,id:saved.rows[0].id,title,fileName:data.fileName});
  } catch(error) { if(req.file?.path){try{fs.unlinkSync(req.file.path)}catch(_){}} console.error('SECRETARY DOCUMENT UPLOAD ERROR:',error); return res.status(500).json({error:'Document upload failed.'}); }
});

app.get('/api/secretary/documents/:id/download', requireAdmin, async (req,res) => {
  try {
    await secretaryTableReady;
    const id=Number(req.params.id), found=await pool.query(`SELECT data FROM nsf_secretary_records WHERE id=$1 AND category='document'`,[id]);
    if(!found.rows.length) return res.status(404).json({error:'Document was not found.'});
    const data=found.rows[0].data||{}, stored=path.basename(String(data.storedName||'')), fullPath=path.join(secretaryPrivateDir,stored);
    if(!stored||!fs.existsSync(fullPath)) return res.status(404).json({error:'The file is not available on the server.'});
    return res.download(fullPath,path.basename(String(data.fileName||'NSF-document')));
  } catch(error) { console.error('SECRETARY DOCUMENT DOWNLOAD ERROR:',error); return res.status(500).json({error:'Document download failed.'}); }
});

const internshipTableReady = initializeTable(`
    CREATE TABLE IF NOT EXISTS internships (
      id SERIAL PRIMARY KEY,
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `, 'INTERNSHIP');


/* ---------------------------------------------------------
   EDIT INTERNSHIP APPLICATION — staged until explicit approval
   --------------------------------------------------------- */
const INTERNSHIP_SYSTEM_FIELDS = new Set([
  'id', 'status', 'studentId', 'internshipId', 'approvedAt', 'issuedAt',
  'rejectedAt', 'revokedAt', 'publicProfileId', 'studentAccount',
  'pendingFormRevision', 'formRevisionStatus',
  'formRevisionSubmittedAt', 'formRevisionApprovedAt'
]);

app.put('/api/internships/:id', requireAdmin, async (req, res) => {
  try {
    await internshipTableReady;
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).json({ error: 'Invalid internship application ID' });
    }
    const incoming = req.body?.pendingFormRevision;
    if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) {
      return res.status(400).json({ error: 'pendingFormRevision object is required' });
    }
    const result = await pool.query(
      'SELECT id, data, created_at FROM internships WHERE id = $1 LIMIT 1',
      [id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Internship application not found' });

    const revision = {};
    for (const [key, value] of Object.entries(incoming)) {
      if (INTERNSHIP_SYSTEM_FIELDS.has(key)) continue;
      if (typeof key !== 'string' || key.length > 100) continue;
      if (typeof value === 'string') revision[key] = value.slice(0, 5000);
      else if (Array.isArray(value)) revision[key] = value.slice(0, 100).map(v => String(v).slice(0, 500));
      else if (value === null || typeof value === 'number' || typeof value === 'boolean') revision[key] = value;
    }

    const current = result.rows[0].data || {};
    const updated = {
      ...current,
      pendingFormRevision: revision,
      formRevisionStatus: 'pending_approval',
      formRevisionSubmittedAt: new Date().toISOString(),
      formRevisionApprovedAt: null
    };
    const saved = await pool.query(
      'UPDATE internships SET data = $1::jsonb WHERE id = $2 RETURNING id, data, created_at',
      [JSON.stringify(updated), id]
    );
    return res.json({ id, ...(saved.rows[0].data || {}), submittedAt: saved.rows[0].created_at });
  } catch (error) {
    console.error('PUT /api/internships/:id:', error);
    return res.status(500).json({ error: 'Could not save edited application for approval.' });
  }
});

app.post('/api/internships/:id/approve-edit', requireAdmin, async (req, res) => {
  try {
    await internshipTableReady;
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).json({ error: 'Invalid internship application ID' });
    }
    const result = await pool.query(
      'SELECT id, data, created_at FROM internships WHERE id = $1 LIMIT 1',
      [id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Internship application not found' });
    const current = result.rows[0].data || {};
    const revision = current.pendingFormRevision;
    if (!revision || typeof revision !== 'object' || Array.isArray(revision) || current.formRevisionStatus !== 'pending_approval') {
      return res.status(409).json({ error: 'No edited application is waiting for approval.' });
    }
    const approved = { ...current };
    for (const [key, value] of Object.entries(revision)) {
      if (!INTERNSHIP_SYSTEM_FIELDS.has(key)) approved[key] = value;
    }
    approved.pendingFormRevision = null;
    approved.formRevisionStatus = 'approved';
    approved.formRevisionApprovedAt = new Date().toISOString();
    const saved = await pool.query(
      'UPDATE internships SET data = $1::jsonb WHERE id = $2 RETURNING id, data, created_at',
      [JSON.stringify(approved), id]
    );
    return res.json({ id, ...(saved.rows[0].data || {}), submittedAt: saved.rows[0].created_at });
  } catch (error) {
    console.error('POST /api/internships/:id/approve-edit:', error);
    return res.status(500).json({ error: 'Could not approve edited application.' });
  }
});

/* ---------------------------------------------------------
   ADMIN ATTENDANCE UPDATE
   --------------------------------------------------------- */
app.put('/api/internships/:id/attendance', requireAdmin, async (req, res) => {
  try {
    await internshipTableReady;
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid internship application ID.' });
    const result = await pool.query('SELECT id, data, created_at FROM internships WHERE id=$1 LIMIT 1', [id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Internship application not found' });
    const current = result.rows[0].data || {};
    const totalDays = Math.min(21, Math.max(1, Number(req.body?.totalDays) || 21));
    let days;
    if (Array.isArray(req.body?.days)) {
      days = req.body.days.slice(0, 21).map((d, index) => ({
        day: index + 1,
        date: String(d?.date || '').slice(0, 10),
        status: d?.status === 'present' ? 'present' : 'absent'
      }));
      while (days.length < totalDays) days.push({ day: days.length + 1, date: '', status: 'absent' });
    } else {
      const presentDays = Number(req.body?.presentDays);
      if (!Number.isInteger(presentDays) || presentDays < 0 || presentDays > totalDays) {
        return res.status(400).json({ error: 'Attendance सही दर्ज करें।' });
      }
      const oldDates = Array.isArray(req.body?.dates) ? req.body.dates : [];
      days = Array.from({length: totalDays}, (_, i) => ({
        day: i + 1, date: String(oldDates[i] || '').slice(0, 10),
        status: i < presentDays ? 'present' : 'absent'
      }));
    }
    const presentDays = days.filter(d => d.status === 'present').length;
    const attendance = {
      presentDays, totalDays, absentDays: totalDays - presentDays,
      percentage: Number((presentDays / totalDays * 100).toFixed(1)),
      dates: days.filter(d => d.status === 'present').map(d => d.date).filter(Boolean),
      days, updatedAt: new Date().toISOString(), updatedByRole: req.userRole || 'admin'
    };
    const projectCount = await pool.query(`SELECT COUNT(*)::int AS total FROM project_submissions WHERE (data->>'applicationId') = $1 AND lower(COALESCE(data->>'status','submitted')) = 'approved'`, [String(id)]);
    const projectSubmitted = await pool.query(`SELECT COUNT(*)::int AS total FROM project_submissions WHERE (data->>'applicationId') = $1`, [String(id)]);
    const projectApproved = Number(projectCount.rows[0]?.total || 0) > 0;
    const completionEligible = presentDays === 21 && projectApproved;
    const updated = { ...current, attendance, projectSubmitted: Number(projectSubmitted.rows[0]?.total || 0) > 0, projectApproved, completionEligible };
    const saved = await pool.query('UPDATE internships SET data=$1::jsonb WHERE id=$2 RETURNING id,data,created_at', [JSON.stringify(updated), id]);
    return res.json({ id, ...(saved.rows[0].data || {}), submittedAt: saved.rows[0].created_at });
  } catch (error) {
    console.error('PUT /api/internships/:id/attendance:', error);
    return res.status(500).json({ error: 'Attendance save नहीं हो सकी।' });
  }
});

/* ---------------------------------------------------------
   ADMIN APPROVE ATTENDANCE — persisted in internship JSONB
   --------------------------------------------------------- */
app.post('/api/internships/:id/attendance/approve', requireAdmin, async (req, res) => {
  try {
    await internshipTableReady;
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid internship application ID.' });
    const found = await pool.query('SELECT id,data,created_at FROM internships WHERE id=$1 LIMIT 1', [id]);
    if (!found.rows.length) return res.status(404).json({ error: 'Internship application not found.' });
    const current = found.rows[0].data || {}, attendance = current.attendance || {};
    if (!Array.isArray(attendance.days) || attendance.days.length !== 21 || Number(attendance.totalDays) !== 21) {
      return res.status(409).json({ error: 'पहले 21-day attendance रिकॉर्ड सेव करें।' });
    }
    const approvedAttendance = { ...attendance, approved: true, approvalStatus: 'approved', approvedAt: new Date().toISOString(), approvedByRole: req.userRole || 'admin' };
    const updated = { ...current, attendance: approvedAttendance };
    const saved = await pool.query('UPDATE internships SET data=$1::jsonb WHERE id=$2 RETURNING id,data,created_at', [JSON.stringify(updated), id]);
    nsfClearAdminListCache();
    return res.json({ id, ...(saved.rows[0].data || {}), submittedAt: saved.rows[0].created_at });
  } catch (error) {
    console.error('POST /api/internships/:id/attendance/approve:', error);
    return res.status(500).json({ error: 'Attendance approval नहीं हो सकी।' });
  }
});

/* ---------------------------------------------------------
   APPROVE STUDENT INTERNSHIP
   --------------------------------------------------------- */

app.post(
  '/api/internships/:id/approve',
  requireAdmin,
  async (req, res) => {

    try {

      await internshipTableReady;

      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(id)
      ) {

        return res.status(400)
          .json({
            error:
              'Invalid internship application ID'
          });

      }

      const result =
        await pool.query(
          `SELECT id, data, created_at
           FROM internships
           WHERE id = $1
           LIMIT 1`,
          [id]
        );

      if (
        !result.rows.length
      ) {

        return res.status(404)
          .json({
            error:
              'Internship application not found'
          });

      }

      const row =
        result.rows[0];

      const data = {
        ...(row.data || {})
      };

      /*
       * Keep an already-issued ID stable when an admin
       * opens Approve again. Otherwise generate a new
       * official ID based on the database application ID.
       */
      const internshipId =
        data.internshipId ||
        `NSF-INT-${new Date().getFullYear()}-${String(id).padStart(4, '0')}`;

      const now =
        new Date().toISOString();

      data.status =
        'active';

      data.internshipId =
        internshipId;

      data.approvedAt =
        data.approvedAt ||
        now;

      data.issuedAt =
        data.issuedAt ||
        now;

      data.rejectedAt =
        null;

      data.revokedAt =
        null;

      const updated =
        await pool.query(
          `UPDATE internships
           SET data = $1::jsonb
           WHERE id = $2
           RETURNING id, data, created_at`,
          [
            JSON.stringify(
              data
            ),
            id
          ]
        );

      const updatedRow =
        updated.rows[0];

      res.json({

        ok: true,

        message:
          'Internship approved and Offer Letter enabled',

        id,

        internshipId,

        internship: {

          id:
            updatedRow.id,

          submittedAt:
            updatedRow.created_at,

          ...(updatedRow.data || {})

        }

      });

    } catch (error) {

      console.error(
        'APPROVE INTERNSHIP ERROR:',
        error
      );

      res.status(500)
        .json({
          error:
            'Could not approve internship application'
        });

    }

  }
);


/* ---------------------------------------------------------
   REJECT STUDENT INTERNSHIP
   --------------------------------------------------------- */

app.post(
  '/api/internships/:id/reject',
  requireAdmin,
  async (req, res) => {

    try {

      await internshipTableReady;

      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(id)
      ) {

        return res.status(400)
          .json({
            error:
              'Invalid internship application ID'
          });

      }

      const result =
        await pool.query(
          `SELECT id, data, created_at
           FROM internships
           WHERE id = $1
           LIMIT 1`,
          [id]
        );

      if (
        !result.rows.length
      ) {

        return res.status(404)
          .json({
            error:
              'Internship application not found'
          });

      }

      const data = {
        ...(result.rows[0].data || {})
      };

      data.status =
        'rejected';

      data.rejectedAt =
        new Date().toISOString();

      data.revokedAt =
        null;

      const updated =
        await pool.query(
          `UPDATE internships
           SET data = $1::jsonb
           WHERE id = $2
           RETURNING id, data, created_at`,
          [
            JSON.stringify(
              data
            ),
            id
          ]
        );

      const row =
        updated.rows[0];

      res.json({

        ok: true,

        message:
          'Internship application rejected',

        internship: {

          id:
            row.id,

          submittedAt:
            row.created_at,

          ...(row.data || {})

        }

      });

    } catch (error) {

      console.error(
        'REJECT INTERNSHIP ERROR:',
        error
      );

      res.status(500)
        .json({
          error:
            'Could not reject internship application'
        });

    }

  }
);


/* ---------------------------------------------------------
   REVOKE STUDENT INTERNSHIP APPROVAL
   --------------------------------------------------------- */

app.post(
  '/api/internships/:id/revoke',
  requireAdmin,
  async (req, res) => {

    try {

      await internshipTableReady;

      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(id)
      ) {

        return res.status(400)
          .json({
            error:
              'Invalid internship application ID'
          });

      }

      const result =
        await pool.query(
          `SELECT id, data, created_at
           FROM internships
           WHERE id = $1
           LIMIT 1`,
          [id]
        );

      if (
        !result.rows.length
      ) {

        return res.status(404)
          .json({
            error:
              'Internship application not found'
          });

      }

      const data = {
        ...(result.rows[0].data || {})
      };

      data.status =
        'revoked';

      data.revokedAt =
        new Date().toISOString();

      const updated =
        await pool.query(
          `UPDATE internships
           SET data = $1::jsonb
           WHERE id = $2
           RETURNING id, data, created_at`,
          [
            JSON.stringify(
              data
            ),
            id
          ]
        );

      const row =
        updated.rows[0];

      res.json({

        ok: true,

        message:
          'Internship approval revoked',

        internship: {

          id:
            row.id,

          submittedAt:
            row.created_at,

          ...(row.data || {})

        }

      });

    } catch (error) {

      console.error(
        'REVOKE INTERNSHIP ERROR:',
        error
      );

      res.status(500)
        .json({
          error:
            'Could not revoke internship approval'
        });

    }

  }
);


/* =========================================================
   VOLUNTEER ID SYSTEM
   ========================================================= */


/* ---------------------------------------------------------
   APPROVE VOLUNTEER
   --------------------------------------------------------- */

app.post(
  '/api/volunteers/:id/approve',
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(id)
      ) {

        return res.status(400)
          .json({

            error:
              'Invalid volunteer ID'

          });

      }


      const result =
        await pool.query(

          `SELECT id, data, created_at
           FROM volunteers
           WHERE id = $1
           LIMIT 1`,

          [id]

        );


      if (
        !result.rows.length
      ) {

        return res.status(404)
          .json({

            error:
              'Volunteer application not found'

          });

      }


      const row =
        result.rows[0];


      const data = {
        ...(row.data || {})
      };


      const volunteerId =
        data.volunteerId ||
        `NSF-V-${String(
          row.id
        ).padStart(
          5,
          '0'
        )}`;


      const verificationCode =
        data.verificationCode ||
        crypto
          .randomBytes(16)
          .toString('hex');


      const verificationUrl =
        `${PUBLIC_BASE_URL.replace(
          /\/$/,
          ''
        )}/verify/volunteer/${verificationCode}`;


      const now =
        new Date()
          .toISOString();


      data.status =
        'active';

      data.volunteerId =
        volunteerId;

      data.verificationCode =
        verificationCode;

      data.verificationUrl =
        verificationUrl;

      data.approvedAt =
        data.approvedAt ||
        now;

      data.issuedAt =
        data.issuedAt ||
        now;

      data.rejectedAt =
        null;

      data.revokedAt =
        null;


      const updated =
        await pool.query(

          `UPDATE volunteers
           SET data = $1::jsonb
           WHERE id = $2
           RETURNING id, data, created_at`,

          [
            JSON.stringify(
              data
            ),
            id
          ]

        );


      const updatedRow =
        updated.rows[0];


      res.json({

        ok: true,

        message:
          'Volunteer approved and ID issued',

        volunteerId,

        verificationCode,

        verificationUrl,

        volunteer: {

          id:
            updatedRow.id,

          submittedAt:
            updatedRow.created_at,

          ...(updatedRow.data || {})

        }

      });


    } catch (error) {

      console.error(
        'APPROVE VOLUNTEER ERROR:',
        error
      );

      res.status(500).json({

        error:
          'Could not approve volunteer'

      });

    }

  }
);


/* ---------------------------------------------------------
   REJECT VOLUNTEER
   --------------------------------------------------------- */

app.post(
  '/api/volunteers/:id/reject',
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(id)
      ) {

        return res.status(400)
          .json({

            error:
              'Invalid volunteer ID'

          });

      }


      const result =
        await pool.query(

          `SELECT id, data, created_at
           FROM volunteers
           WHERE id = $1
           LIMIT 1`,

          [id]

        );


      if (
        !result.rows.length
      ) {

        return res.status(404)
          .json({

            error:
              'Volunteer application not found'

          });

      }


      const data = {
        ...(result.rows[0].data || {})
      };


      data.status =
        'rejected';

      data.rejectedAt =
        new Date()
          .toISOString();

      data.revokedAt =
        null;


      const updated =
        await pool.query(

          `UPDATE volunteers
           SET data = $1::jsonb
           WHERE id = $2
           RETURNING id, data, created_at`,

          [
            JSON.stringify(
              data
            ),
            id
          ]

        );


      const row =
        updated.rows[0];


      res.json({

        ok: true,

        message:
          'Volunteer application rejected',

        volunteer: {

          id:
            row.id,

          submittedAt:
            row.created_at,

          ...(row.data || {})

        }

      });


    } catch (error) {

      console.error(
        'REJECT VOLUNTEER ERROR:',
        error
      );

      res.status(500).json({

        error:
          'Could not reject volunteer'

      });

    }

  }
);


/* =========================================================
   REVOKE VOLUNTEER
   ========================================================= */

app.post(
  '/api/volunteers/:id/revoke',
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(id)
      ) {

        return res.status(400)
          .json({

            error:
              'Invalid volunteer ID'

          });

      }


      const result =
        await pool.query(

          `SELECT id, data, created_at
           FROM volunteers
           WHERE id = $1
           LIMIT 1`,

          [id]

        );


      if (
        !result.rows.length
      ) {

        return res.status(404)
          .json({

            error:
              'Volunteer application not found'

          });

      }


      const data = {
        ...(result.rows[0].data || {})
      };


      data.status =
        'revoked';

      data.revokedAt =
        new Date()
          .toISOString();


      const updated =
        await pool.query(

          `UPDATE volunteers
           SET data = $1::jsonb
           WHERE id = $2
           RETURNING id, data, created_at`,

          [
            JSON.stringify(
              data
            ),
            id
          ]

        );


      const row =
        updated.rows[0];


      res.json({

        ok: true,

        message:
          'Volunteer ID revoked',

        volunteer: {

          id:
            row.id,

          submittedAt:
            row.created_at,

          ...(row.data || {})

        }

      });


    } catch (error) {

      console.error(
        'REVOKE VOLUNTEER ERROR:',
        error
      );

      res.status(500).json({

        error:
          'Could not revoke volunteer'

      });

    }

  }
);


/* =========================================================
   VOLUNTEER VERIFICATION API
   ========================================================= */

app.get(
  '/api/volunteers/verify/:code',
  async (req, res) => {

    try {

      const code =
        String(
          req.params.code || ''
        ).trim();


      if (!code) {

        return res.status(400)
          .json({

            verified:
              false,

            status:
              'INVALID'

          });

      }


      const result =
        await pool.query(

          `SELECT id, data, created_at
           FROM volunteers
           WHERE data->>'verificationCode' = $1
           LIMIT 1`,

          [code]

        );


      if (
        !result.rows.length
      ) {

        return res.json({

          verified:
            false,

          status:
            'NOT FOUND'

        });

      }


      const row =
        result.rows[0];


      const data =
        row.data || {};


      const verified =
        data.status ===
        'active';


      res.json({

        verified,

        status:
          data.status ||
          'pending',

        volunteerId:
          data.volunteerId ||
          null,

        name:
          data.name ||
          null,

        city:
          data.city ||
          null,

        area:
          data.area ||
          null,

        skills:
          data.skills ||
          null

      });


    } catch (error) {

      console.error(
        'VERIFY VOLUNTEER ERROR:',
        error
      );

      res.status(500).json({

        verified:
          false,

        status:
          'SERVICE ERROR'

      });

    }

  }
);


/* =========================================================
   VOLUNTEER VERIFICATION PAGE
   ========================================================= */

app.get(
  '/verify/volunteer/:code',
  (req, res) => {

    const code =
      encodeURIComponent(
        req.params.code
      );


    res.send(`<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width, initial-scale=1.0"
>

<title>
Nisha Seva Foundation - Volunteer Verification
</title>

<style>

body {

  margin: 0;

  min-height: 100vh;

  display: flex;

  align-items: center;

  justify-content: center;

  background:
    #f1f5f9;

  font-family:
    Arial,
    sans-serif;

}

.card {

  width:
    min(92%, 600px);

  background:
    white;

  padding:
    30px;

  border-radius:
    18px;

  box-shadow:
    0 10px 30px
    rgba(0,0,0,0.08);

}

.logo {

  text-align:
    center;

  font-size:
    42px;

}

h1 {

  text-align:
    center;

  margin:
    0 0 8px;

}

.subtitle {

  text-align:
    center;

  color:
    #64748b;

  margin-bottom:
    25px;

}

.status {

  padding:
    15px;

  border-radius:
    12px;

  text-align:
    center;

  font-weight:
    bold;

  margin-bottom:
    20px;

}

.loading {

  background:
    #e2e8f0;

  color:
    #334155;

}

.active {

  background:
    #dcfce7;

  color:
    #166534;

}

.invalid {

  background:
    #fee2e2;

  color:
    #991b1b;

}

.row {

  display:
    flex;

  justify-content:
    space-between;

  gap:
    20px;

  padding:
    13px 0;

  border-bottom:
    1px solid #e2e8f0;

}

.label {

  font-weight:
    bold;

  color:
    #475569;

}

.value {

  text-align:
    right;

  word-break:
    break-word;

}

.footer {

  margin-top:
    25px;

  text-align:
    center;

  font-size:
    13px;

  color:
    #64748b;

}

</style>

</head>

<body>

<div class="card">

<div class="logo">
🌿
</div>

<h1>
Nisha Seva Foundation
</h1>

<div class="subtitle">
Volunteer ID Verification
</div>

<div
  id="status"
  class="status loading"
>
Verifying Volunteer ID...
</div>

<div id="details">
</div>

<div class="footer">
This page verifies the volunteer ID issued by Nisha Seva Foundation.
</div>

</div>


<script>

(async function () {

  const statusElement =
    document.getElementById(
      'status'
    );

  const detailsElement =
    document.getElementById(
      'details'
    );


  try {

    const response =
      await fetch(
        '/api/volunteers/verify/${code}'
      );


    const data =
      await response.json();


    if (
      data.verified
    ) {

      statusElement.className =
        'status active';

      statusElement.textContent =
        '✓ VERIFIED — ACTIVE VOLUNTEER';

    }

    else {

      statusElement.className =
        'status invalid';

      statusElement.textContent =
        '✕ NOT ACTIVE — ' +
        String(
          data.status ||
          'NOT VERIFIED'
        ).toUpperCase();

    }


    const rows = [

      [
        'Volunteer ID',
        data.volunteerId || '—'
      ],

      [
        'Name',
        data.name || '—'
      ],

      [
        'City',
        data.city || '—'
      ],

      [
        'Area',
        data.area || '—'
      ],

      [
        'Skills',
        data.skills || '—'
      ]

    ];


    detailsElement.innerHTML =
      rows.map(
        function (row) {

          return \`
            <div class="row">

              <div class="label">
                \${escapeHTML(row[0])}
              </div>

              <div class="value">
                \${escapeHTML(row[1])}
              </div>

            </div>
          \`;

        }
      ).join('');


  }

  catch (error) {

    statusElement.className =
      'status invalid';

    statusElement.textContent =
      'Verification service unavailable';

  }


  function escapeHTML(
    value
  ) {

    return String(value)

      .replaceAll(
        '&',
        '&amp;'
      )

      .replaceAll(
        '<',
        '&lt;'
      )

      .replaceAll(
        '>',
        '&gt;'
      )

      .replaceAll(
        '"',
        '&quot;'
      )

      .replaceAll(
        "'",
        '&#039;'
      );

  }

})();

</script>

</body>

</html>`);

  }

);


/* =========================================================
   MAIN WEBSITE
   ========================================================= */

app.get(
  '/',
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        'index.html'
      )
    );

  }
);


/* =========================================================
   LOGO
   ========================================================= */

app.get(
  '/logo.jpeg',
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        'logo.jpeg'
      )
    );

  }
);


/* =========================================================
   DONATION QR
   ========================================================= */

app.get(
  '/donation-qr.jpg',
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        'donation-qr.jpg'
      )
    );

  }
);



/* =========================================================
   STUDENT PROJECT SUBMISSIONS
   Public POST + Admin GET/DELETE
   ========================================================= */
const projectSubmissionTableReady = initializeTable(`
  CREATE TABLE IF NOT EXISTS project_submissions (
    id SERIAL PRIMARY KEY,
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`, 'PROJECT SUBMISSIONS');

app.post('/api/projectSubmissions', publicFormLimiter, async (req, res) => {
  try {
    await projectSubmissionTableReady;
    const body = req.body || {};
    if (!body.studentName || !body.email || !body.phone || !body.college ||
        !body.title || !body.description || body.declarationAccepted !== true) {
      return res.status(400).json({ error: 'Please complete all required fields and accept the declaration.' });
    }
    const fileData = body.projectFile;
    if (fileData && fileData.data) {
      const match = /^data:([^;,]+)?;base64,([A-Za-z0-9+/=\s]+)$/.exec(fileData.data);
      if (!match) return res.status(400).json({ error: 'Project file format is invalid. Please choose the file again.' });
      const base64 = match[2].replace(/\s/g, '');
      const approxBytes = Math.floor(base64.length * 3 / 4) - (base64.endsWith('==') ? 2 : base64.endsWith('=') ? 1 : 0);
      if (approxBytes > 20 * 1024 * 1024) {
        return res.status(413).json({ error: 'Project file must be 20 MB or smaller.' });
      }
    }
    const submission = { ...body, status: 'pending', submittedAt: new Date().toISOString() };
    const result = await pool.query(
      'INSERT INTO project_submissions (data) VALUES ($1::jsonb) RETURNING id',
      [JSON.stringify(submission)]
    );
    nsfClearAdminListCache();
    return res.status(201).json({ ok: true, id: result.rows[0].id, message: 'Project submitted successfully.' });
  } catch (error) {
    console.error('POST /api/projectSubmissions:', error);
    if (error && error.type === 'entity.too.large') {
      return res.status(413).json({ error: 'Request too large. Please submit a project file of 20 MB or smaller.' });
    }
    return res.status(500).json({ error: 'Project submission could not be saved. Please try again later.' });
  }
});

app.get('/api/projectSubmissions', requireAdmin, async (req, res) => {
  try {
    await projectSubmissionTableReady;
    const summaryOnly = req.query.summary === '1';
    const parsedLimit = Number.parseInt(req.query.limit || '100', 10);
    const limit = Math.min(500, Math.max(1, Number.isFinite(parsedLimit) ? parsedLimit : 100));
    const parsedOffset = Number.parseInt(req.query.offset || '0', 10);
    const offset = Math.min(1000000, Math.max(0, Number.isFinite(parsedOffset) ? parsedOffset : 0));
    const projectCacheKey = `project-summary:${limit}:${offset}`;
    const loadProjectRows = async () => {
      const sql = summaryOnly
        ? `SELECT id, created_at, data
           FROM nsf_project_submission_list_cache
           ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2`
        : 'SELECT id, data, created_at FROM project_submissions ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2';
      const queryStarted = process.hrtime.bigint();
      const result = await pool.query(sql, [limit, offset]);
      const queryMs = Number(process.hrtime.bigint() - queryStarted) / 1e6;
      const rows = result.rows.map(row => ({
        id: row.id,
        submittedAt: row.created_at,
        ...(summaryOnly ? (row.data || {}) : (row.data || {}))
      }));
      return { rows, queryMs };
    };

    if (summaryOnly) {
      const loaded = await nsfLoadCachedList(projectCacheKey, loadProjectRows);
      res.set('X-NSF-Cache', loaded.cache);
      res.set('X-NSF-DB-Query-Ms', loaded.cache === 'MISS' ? 'measured' : 'cached');
      res.set('X-NSF-Page-Limit', String(limit));
      res.set('X-NSF-Page-Offset', String(offset));
      res.set('Cache-Control', 'private, no-store');
      return res.json(loaded.value.rows);
    }

    const loaded = await loadProjectRows();
    res.set('X-NSF-DB-Query-Ms', loaded.queryMs.toFixed(1));
    res.set('X-NSF-Page-Limit', String(limit));
    res.set('X-NSF-Page-Offset', String(offset));
    res.set('Cache-Control', 'private, no-store');
    return res.json(loaded.rows);
  } catch (error) {
    console.error('GET /api/projectSubmissions:', error);
    return res.status(500).json({ error: 'Could not load project submissions.' });
  }
});

app.get('/api/projectSubmissions/:id/file', requireAdmin, async (req, res) => {
  try {
    await projectSubmissionTableReady;
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid project ID.' });
    const result = await pool.query(
      `SELECT data->'projectFile' AS file FROM project_submissions WHERE id=$1 LIMIT 1`,
      [id]
    );
    if (!result.rows.length || !result.rows[0].file?.data) return res.status(404).json({ error: 'Project file not found.' });
    res.set('Cache-Control', 'private, no-store');
    return res.json({ projectFile: result.rows[0].file });
  } catch (error) {
    console.error('GET project file error:', error);
    return res.status(500).json({ error: 'Could not load project file.' });
  }
});

app.post('/api/projectSubmissions/:id/review', requireAdmin, async (req, res) => {
  try {
    await projectSubmissionTableReady;
    const id = Number(req.params.id);
    const status = String(req.body?.status || '').toLowerCase();
    if (!Number.isSafeInteger(id) || id < 1 || !['approved','rejected'].includes(status)) {
      return res.status(400).json({ error: 'Invalid project review request.' });
    }

    // Persist the review independently so an internship-linking failure cannot undo approval.
    const found = await pool.query('SELECT id,data FROM project_submissions WHERE id=$1 LIMIT 1', [id]);
    if (!found.rows.length) return res.status(404).json({ error: 'Project submission not found.' });
    const data = { ...(found.rows[0].data || {}), status, reviewedAt: new Date().toISOString(), reviewedByRole: req.userRole || 'admin' };
    let applicationId = Number(data.applicationId || 0);

    // Safely link legacy submissions only when email/reference resolves to exactly one application.
    if (!Number.isSafeInteger(applicationId) || applicationId < 1) {
      const email = String(data.email || data.studentEmail || '').trim().toLowerCase();
      const internshipRef = String(data.internshipId || data.referenceNo || data.applicationReference || '').trim().toLowerCase();
      let candidates = [];
      if (email) {
        const matchByEmail = await pool.query(`SELECT id FROM internships WHERE lower(COALESCE(data->>'email',data->>'studentEmail',''))=$1`, [email]);
        candidates = matchByEmail.rows;
      }
      if (candidates.length !== 1 && internshipRef) {
        const matchByRef = await pool.query(`SELECT id FROM internships WHERE lower(COALESCE(data->>'internshipId',data->>'referenceNo',data->>'applicationReference',''))=$1`, [internshipRef]);
        candidates = matchByRef.rows;
      }
      if (candidates.length === 1) applicationId = Number(candidates[0].id);
      else applicationId = 0;
    }
    if (applicationId > 0) data.applicationId = applicationId;

    const saved = await pool.query('UPDATE project_submissions SET data=$1::jsonb WHERE id=$2 RETURNING id', [JSON.stringify(data), id]);
    if (!saved.rowCount) return res.status(404).json({ error: 'Project submission not found.' });

    // Internship linking/eligibility is secondary: report/log its failure, but keep the review saved.
    let internshipUpdate = 'not-linked';
    if (applicationId > 0) {
      try {
        const appRow = await pool.query('SELECT id,data FROM internships WHERE id=$1 LIMIT 1', [applicationId]);
        if (appRow.rows.length) {
          const appData = appRow.rows[0].data || {};
          const approvedCount = await pool.query(`SELECT COUNT(*)::int AS total FROM project_submissions WHERE (data->>'applicationId')=$1 AND lower(COALESCE(data->>'status','submitted'))='approved'`, [String(applicationId)]);
          const projectApproved = Number(approvedCount.rows[0]?.total || 0) > 0;
          const attendance = appData.attendance || {};
          const completionEligible = Number(attendance.presentDays || 0) === 21 && projectApproved;
          await pool.query('UPDATE internships SET data=$1::jsonb WHERE id=$2', [JSON.stringify({...appData, projectSubmitted:true, projectApproved, completionEligible}), applicationId]);
          internshipUpdate = 'updated';
        } else internshipUpdate = 'application-not-found';
      } catch (linkError) {
        internshipUpdate = 'failed';
        console.error('Project review saved, but internship linkage update failed:', linkError);
      }
    }
    nsfClearAdminListCache();
    return res.json({ ok:true, id, status, applicationId: applicationId || null, internshipUpdate });
  } catch (error) {
    console.error('POST /api/projectSubmissions/:id/review failed:', error?.code || '', error?.message || error, error?.detail || '', error?.constraint || '');
    return res.status(500).json({ error: 'Project review could not be saved.', code: error?.code || null });
  }
});

app.delete('/api/projectSubmissions/:id', requireAdmin, async (req, res) => {
  try {
    await projectSubmissionTableReady;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid project submission ID.' });
    const result = await pool.query('DELETE FROM project_submissions WHERE id = $1 RETURNING id', [id]);
    if (!result.rowCount) return res.status(404).json({ error: 'Project submission not found.' });
    nsfClearAdminListCache();
    return res.json({ ok: true });
  } catch (error) {
    console.error('DELETE /api/projectSubmissions:', error);
    return res.status(500).json({ error: 'Could not delete project submission.' });
  }
});


/* =========================================================
   ERROR HANDLER
   ========================================================= */

app.use(
  (
    err,
    req,
    res,
    next
  ) => {

    console.error(
      'SERVER ERROR:',
      err
    );


    if (
      res.headersSent
    ) {

      return next(err);

    }


    res.status(500).json({

      error:
        err.message ||
        'Internal server error'

    });

  }
);



/* =========================================================
   STUDENT SELF-SERVICE PORTAL
   Student accounts use scrypt password hashes; public QR
   profiles intentionally exclude Aadhaar and document files.
   ========================================================= */
const studentSessions = new Map();
const STUDENT_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const studentAccountsTableReady = initializeTable(`
  CREATE TABLE IF NOT EXISTS internship_student_accounts (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    public_id TEXT NOT NULL UNIQUE,
    internship_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`, 'STUDENT ACCOUNTS');

function makeStudentToken(){ return crypto.randomBytes(32).toString('hex'); }
function makePublicStudentId(){ return crypto.randomBytes(16).toString('hex'); }
function studentAuth(req,res,next){
  const header=req.headers.authorization||'';
  const token=header.startsWith('Bearer ')?header.slice(7):'';
  const session=token&&studentSessions.get(token);
  if(!session||session.expiresAt<Date.now()){
    if(token) studentSessions.delete(token);
    return res.status(401).json({error:'Student login session expired. Please log in again.'});
  }
  req.studentAccountId=session.accountId;
  next();
}
function hashStudentPassword(password,salt){
  return new Promise((resolve,reject)=>crypto.scrypt(password,salt,64,(err,derived)=>err?reject(err):resolve(derived.toString('hex'))));
}
function studentPublicUrl(publicId){
  const base=(process.env.STUDENT_PORTAL_URL||'https://nishasevafoundation.org/student-portal.html').replace(/\/$/,'');
  return `${base}?profile=${encodeURIComponent(publicId)}`;
}
async function getStudentAccount(accountId){
  const result=await pool.query('SELECT id, username, email, public_id, internship_id, created_at FROM internship_student_accounts WHERE id=$1 LIMIT 1',[accountId]);
  return result.rows[0]||null;
}
async function getStudentApplication(account){
  if(!account || !account.internship_id) return null;
  await internshipTableReady;
  const result=await pool.query('SELECT id, data, created_at FROM internships WHERE id=$1 LIMIT 1',[account.internship_id]);
  if(!result.rows.length) return null;
  return {id:result.rows[0].id,submittedAt:result.rows[0].created_at,...(result.rows[0].data||{})};
}

const studentProjectSubmissionTableReady = projectSubmissionTableReady;
app.get('/api/student/projects', studentAuth, async (req, res) => {
  try {
    await Promise.all([studentAccountsTableReady, studentProjectSubmissionTableReady]);
    const account = await getStudentAccount(req.studentAccountId);
    if (!account) return res.status(404).json({ error: 'Student account नहीं मिला।' });
    const result = await pool.query(
      `SELECT id,
              jsonb_set(
                data,
                '{projectFile}',
                COALESCE((data->'projectFile') - 'data', 'null'::jsonb),
                true
              ) AS data,
              created_at
         FROM project_submissions
        WHERE (data->>'studentAccountId') = $1
        ORDER BY created_at DESC
        LIMIT 100`,
      [String(account.id)]
    );
    return res.json({ projects: result.rows.map(r => ({ id:r.id, ...(r.data || {}), submittedAt:r.created_at })) });
  } catch (error) {
    console.error('GET /api/student/projects:', error);
    return res.status(500).json({ error: 'Projects load नहीं हो सके।' });
  }
});
app.post('/api/student/projects', studentAuth, publicFormLimiter, async (req, res) => {
  try {
    await Promise.all([studentAccountsTableReady, internshipTableReady, studentProjectSubmissionTableReady]);
    const account = await getStudentAccount(req.studentAccountId);
    if (!account) return res.status(404).json({ error: 'Student account नहीं मिला।' });
    const appResult = await pool.query('SELECT id,data FROM internships WHERE id=$1 LIMIT 1', [account.internship_id]);
    if (!appResult.rows.length) return res.status(404).json({ error: 'Internship application नहीं मिला।' });
    const body = req.body || {};
    const title = String(body.title || '').trim().slice(0, 160);
    const description = String(body.description || '').trim().slice(0, 5000);
    const file = body.projectFile || {};
    const match = /^data:(application\/pdf|image\/(?:jpeg|jpg));base64,([A-Za-z0-9+/=\s]+)$/i.exec(String(file.data || ''));
    if (!title || !description || !match) return res.status(400).json({ error: 'Project title, description और PDF/JPG/JPEG file जरूरी हैं।' });
    const base64 = match[2].replace(/\s/g, '');
    const bytes = Math.floor(base64.length * 3 / 4) - (base64.endsWith('==') ? 2 : base64.endsWith('=') ? 1 : 0);
    if (bytes > 20 * 1024 * 1024) return res.status(413).json({ error: 'Project file अधिकतम 20 MB हो सकती है।' });
    const appData = appResult.rows[0].data || {};
    const submission = {
      studentAccountId: String(account.id), applicationId: account.internship_id,
      studentName: appData.studentName || appData.name || account.username,
      email: account.email, phone: appData.mobile || appData.phone || '',
      college: appData.collegeName || appData.educationCollege || '',
      internshipId: appData.internshipId || `NSF-INT-${account.internship_id}`,
      title, description, projectFile: {
        name: String(file.name || 'project-file').replace(/[^a-z0-9._ -]/gi, '_').slice(0, 180),
        type: match[1].toLowerCase(), data: String(file.data)
      },
      status: 'submitted', submittedAt: new Date().toISOString()
    };
    const saved = await pool.query('INSERT INTO project_submissions (data) VALUES ($1::jsonb) RETURNING id,created_at', [JSON.stringify(submission)]);
    const attendance = appData.attendance || {};
    const eligible = Number(attendance.presentDays || 0) >= 21;
    const updatedApp = { ...appData, projectSubmitted: true, projectSubmittedAt: saved.rows[0].created_at, completionEligible: eligible };
    await pool.query('UPDATE internships SET data=$1::jsonb WHERE id=$2', [JSON.stringify(updatedApp), account.internship_id]);
    return res.status(201).json({ ok:true, id:saved.rows[0].id, completionEligible:eligible, message:'Project successfully submit हो गया।' });
  } catch (error) {
    console.error('POST /api/student/projects:', error);
    if (error?.type === 'entity.too.large') return res.status(413).json({ error:'Project file अधिकतम 20 MB हो सकती है।' });
    return res.status(500).json({ error:'Project submit नहीं हो सका।' });
  }
});

const passwordResetTableReady = initializeTable(`
  CREATE TABLE IF NOT EXISTS internship_password_resets (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`, 'PASSWORD RESET');
const resetRequestLimiter = new Map();
function makeOtpHash(otp, salt) { return crypto.createHash('sha256').update(`${salt}:${otp}`).digest('hex'); }
function getMailTransport() {
  const port = Number(process.env.SMTP_PORT || 465);
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.hostinger.com',
    port,
    secure: String(process.env.SMTP_SECURE || (port === 465 ? 'true' : 'false')).toLowerCase() === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000
  });
}
app.post('/api/student/forgot-password', authLimiter, async (req,res) => {
  const email = String((req.body||{}).email||'').trim().toLowerCase();
  const generic = {ok:true,message:'यदि यह ईमेल Student Portal अकाउंट से जुड़ा है, तो OTP भेज दिया गया है।'};
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(200).json(generic);
  const now = Date.now();
  const last = resetRequestLimiter.get(email) || 0;
  if (now - last < 60 * 1000) return res.status(200).json(generic);
  resetRequestLimiter.set(email, now);
  try {
    await Promise.all([studentAccountsTableReady,passwordResetTableReady]);
    const account = await pool.query('SELECT id FROM internship_student_accounts WHERE lower(email)=lower($1) LIMIT 1',[email]);
    if (!account.rows.length) return res.status(200).json(generic);
    if (!process.env.SMTP_USER || !process.env.SMTP_PASS) throw new Error('SMTP credentials are not configured');
    const otp = String(crypto.randomInt(100000,1000000));
    const salt = crypto.randomBytes(16).toString('hex');
    const otpHash = makeOtpHash(otp,salt);
    await pool.query('UPDATE internship_password_resets SET used=TRUE WHERE lower(email)=lower($1) AND used=FALSE',[email]);
    await pool.query('INSERT INTO internship_password_resets (email,otp_hash,expires_at,attempts,used) VALUES ($1,$2,$3,0,FALSE)',[email,`${salt}:${otpHash}`,new Date(Date.now()+10*60*1000)]);
    const transport = getMailTransport();
    await transport.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: email,
      subject: 'Nisha Seva Foundation Student Portal — Password Reset OTP',
      text: `Your password reset OTP is ${otp}. It expires in 10 minutes. If you did not request this, ignore this email.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:24px;border:1px solid #dfe8e2;border-radius:16px"><h2 style="color:#0f5132">Nisha Seva Foundation</h2><p>Your Student Portal password reset code is:</p><p style="font-size:32px;font-weight:bold;letter-spacing:8px">${otp}</p><p>This code expires in 10 minutes. Never share it with anyone.</p></div>`
    });
    return res.status(200).json(generic);
  } catch(error) {
    console.error('STUDENT FORGOT PASSWORD ERROR:',error.message);
    return res.status(200).json(generic);
  }
});
app.post('/api/student/reset-password', authLimiter, async (req,res) => {
  try {
    await Promise.all([studentAccountsTableReady,passwordResetTableReady]);
    const body=req.body||{};
    const email=String(body.email||'').trim().toLowerCase();
    const otp=String(body.otp||'').trim();
    const newPassword=String(body.newPassword||'');
    if (!/^\S+@\S+\.\S+$/.test(email) || !/^\d{6}$/.test(otp)) return res.status(400).json({error:'ईमेल और 6 अंकों का OTP सही भरें।'});
    if (newPassword.length<10) return res.status(400).json({error:'नया पासवर्ड कम से कम 10 characters का होना चाहिए।'});
    const result=await pool.query('SELECT * FROM internship_password_resets WHERE lower(email)=lower($1) AND used=FALSE AND expires_at>NOW() ORDER BY created_at DESC LIMIT 1',[email]);
    if (!result.rows.length) return res.status(400).json({error:'OTP गलत है या उसकी समय-सीमा समाप्त हो गई है। नया OTP लें।'});
    const reset=result.rows[0];
    if (reset.attempts>=5) return res.status(429).json({error:'बहुत अधिक प्रयास हुए। नया OTP लें।'});
    const [salt,storedHash]=String(reset.otp_hash).split(':');
    const incomingHash=makeOtpHash(otp,salt);
    if (incomingHash!==storedHash) {
      await pool.query('UPDATE internship_password_resets SET attempts=attempts+1 WHERE id=$1',[reset.id]);
      return res.status(400).json({error:'OTP गलत है।'});
    }
    const saltNew=crypto.randomBytes(16).toString('hex');
    const passwordHash=await hashStudentPassword(newPassword,saltNew);
    await pool.query('UPDATE internship_student_accounts SET password_salt=$1,password_hash=$2,updated_at=NOW() WHERE lower(email)=lower($3)',[saltNew,passwordHash,email]);
    await pool.query('UPDATE internship_password_resets SET used=TRUE WHERE id=$1',[reset.id]);
    for (const [token,session] of studentSessions.entries()) {
      if (session.accountId) {
        const acc=await pool.query('SELECT email FROM internship_student_accounts WHERE id=$1',[session.accountId]);
        if (acc.rows[0] && String(acc.rows[0].email).toLowerCase()===email) studentSessions.delete(token);
      }
    }
    return res.json({ok:true,message:'पासवर्ड बदल गया है। अब नए पासवर्ड से Login करें।'});
  } catch(error) {
    console.error('STUDENT RESET PASSWORD ERROR:',error);
    return res.status(500).json({error:'पासवर्ड रीसेट नहीं हो सका।'});
  }
});

app.post('/api/student/signup', authLimiter, async (req,res)=>{
  try {
    await Promise.all([studentAccountsTableReady, internshipTableReady]);
    const body = req.body || {};
    const username = String(body.username || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const referenceNo = String(body.referenceNo || body.refNo || '').trim().toUpperCase();
    if (!/^[a-zA-Z0-9_.-]{4,32}$/.test(username)) return res.status(400).json({error:'Username 4–32 characters का रखें; letters, numbers, dot, underscore या hyphen इस्तेमाल करें।'});
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({error:'Valid email address भरें।'});
    if (password.length < 10) return res.status(400).json({error:'Password कम से कम 10 characters का होना चाहिए।'});
    if (!/^NSF-INT-\d+$/.test(referenceNo)) return res.status(400).json({error:'अपने Internship Application का सही Reference Number भरें।'});
    const appId = Number(referenceNo.replace('NSF-INT-',''));
    const appResult = await pool.query('SELECT id,data,created_at FROM internships WHERE id=$1 LIMIT 1',[appId]);
    if (!appResult.rows.length) return res.status(403).json({error:'इस Reference Number से Internship Application नहीं मिला।'});
    const appRow = appResult.rows[0];
    const appData = appRow.data || {};
    const applicationEmail = String(appData.email || '').trim().toLowerCase();
    const savedReference = String(appData.referenceNo || appData.applicationReference || '').toUpperCase();
    if (applicationEmail !== email || (savedReference && savedReference !== referenceNo)) {
      return res.status(403).json({error:'Reference Number और आवेदन में दर्ज ईमेल का मिलान नहीं हुआ।'});
    }
    if (!savedReference) {
      appData.referenceNo = referenceNo;
      appData.applicationReference = referenceNo;
      await pool.query('UPDATE internships SET data=$1::jsonb WHERE id=$2',[JSON.stringify(appData),appRow.id]);
    }
    const exists = await pool.query('SELECT id FROM internship_student_accounts WHERE internship_id=$1 OR lower(email)=lower($2) LIMIT 1',[appRow.id,email]);
    if (exists.rows.length) return res.status(409).json({error:'इस आवेदन के लिए अकाउंट पहले से बना है। Login या Forgot Password इस्तेमाल करें।'});
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = await hashStudentPassword(password,salt);
    const publicId = makePublicStudentId();
    const accountResult = await pool.query(
      'INSERT INTO internship_student_accounts (username,email,password_salt,password_hash,public_id,internship_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,username,email,public_id,internship_id,created_at',
      [username,email,salt,passwordHash,publicId,appRow.id]
    );
    const account = accountResult.rows[0];
    const token = makeStudentToken();
    studentSessions.set(token,{accountId:account.id,expiresAt:Date.now()+STUDENT_SESSION_TTL_MS});
    return res.status(201).json({ok:true,token,student:{id:account.id,username:account.username,email:account.email,publicId:account.public_id,uniqueUrl:studentPublicUrl(account.public_id),application:{id:appRow.id,...appData,submittedAt:appRow.created_at}}});
  } catch(error) {
    if (error.code === '23505') return res.status(409).json({error:'Username, email या internship application के लिए अकाउंट पहले से registered है।'});
    console.error('STUDENT SIGNUP ERROR:',error);
    return res.status(500).json({error:'Student account नहीं बन सका। कृपया बाद में प्रयास करें।'});
  }
});

app.post('/api/student/login', authLimiter, async (req,res)=>{
  try{
    await studentAccountsTableReady;
    const usernameOrEmail=String((req.body||{}).username||'').trim();
    const password=String((req.body||{}).password||'');
    const result=await pool.query('SELECT * FROM internship_student_accounts WHERE lower(username)=lower($1) OR lower(email)=lower($1) LIMIT 1',[usernameOrEmail]);
    if(!result.rows.length) return res.status(401).json({error:'Username/Email या password गलत है।'});
    const row=result.rows[0];
    const hash=await hashStudentPassword(password,row.password_salt);
    const a=Buffer.from(hash,'hex'),b=Buffer.from(row.password_hash,'hex');
    if(a.length!==b.length||!crypto.timingSafeEqual(a,b)) return res.status(401).json({error:'Username/Email या password गलत है।'});
    const token=makeStudentToken();
    studentSessions.set(token,{accountId:row.id,expiresAt:Date.now()+STUDENT_SESSION_TTL_MS});
    const account={id:row.id,username:row.username,email:row.email,public_id:row.public_id,internship_id:row.internship_id,created_at:row.created_at};
    const application=await getStudentApplication(account);
    return res.json({ok:true,token,student:{id:row.id,username:row.username,email:row.email,publicId:row.public_id,uniqueUrl:studentPublicUrl(row.public_id),application}});
  }catch(error){console.error('STUDENT LOGIN ERROR:',error);return res.status(500).json({error:'Student login नहीं हो सका।'});}
});

app.get('/api/student/me',studentAuth,async(req,res)=>{
  try{await studentAccountsTableReady;const account=await getStudentAccount(req.studentAccountId);if(!account)return res.status(404).json({error:'Student account नहीं मिला।'});const application=await getStudentApplication(account);res.json({student:{id:account.id,username:account.username,email:account.email,publicId:account.public_id,uniqueUrl:studentPublicUrl(account.public_id)},application});}
  catch(error){console.error('STUDENT ME ERROR:',error);res.status(500).json({error:'Student dashboard data load नहीं हो सका।'});}
});

app.put('/api/student/application',studentAuth,async(req,res)=>{
  try{
    await Promise.all([studentAccountsTableReady,internshipTableReady]);
    const account=await getStudentAccount(req.studentAccountId);
    if(!account)return res.status(404).json({error:'Student account नहीं मिला।'});
    const old=await getStudentApplication(account);
    const incoming=req.body&&req.body.application&&typeof req.body.application==='object'?req.body.application:{};
    const protectedKeys=['id','status','internshipId','approvedAt','issuedAt','rejectedAt','revokedAt','publicProfileId','studentAccount'];
    const merged={...(old||{}),...incoming};
    protectedKeys.forEach(k=>{if(old&&old[k]!==undefined)merged[k]=old[k];});
    merged.studentName=String(merged.studentName||merged.name||'').trim();
    merged.email=account.email;
    merged.studentAccount=true;
    await pool.query('UPDATE internships SET data=$1::jsonb WHERE id=$2',[JSON.stringify(merged),account.internship_id]);
    await pool.query('UPDATE internship_student_accounts SET updated_at=NOW() WHERE id=$1',[account.id]);
    const updated=await getStudentApplication(account);
    res.json({ok:true,application:updated});
  }catch(error){console.error('STUDENT APPLICATION UPDATE ERROR:',error);res.status(500).json({error:'Application update नहीं हो सकी।'});}
});

app.post('/api/student/logout',studentAuth,(req,res)=>{
  const token=(req.headers.authorization||'').slice(7);studentSessions.delete(token);res.json({ok:true});
});

// Authenticated coordinator/admin list for generating QR codes in the coordinator panel.
// Sensitive documents, phone and address are deliberately excluded from this response.
app.get('/api/student/accounts', requireAdmin, async (req, res) => {
  try {
    await Promise.all([studentAccountsTableReady, internshipTableReady]);
    const result = await pool.query(`
      SELECT a.id, a.username, a.email, a.public_id, a.internship_id, a.created_at,
             i.data AS application_data, i.created_at AS application_created_at
      FROM internship_student_accounts a
      LEFT JOIN internships i ON i.id = a.internship_id
      ORDER BY a.created_at DESC
    `);
    const students = result.rows.map(row => {
      const d = row.application_data || {};
      return {
        id: row.id,
        username: row.username,
        email: row.email,
        studentName: d.studentName || d.name || row.username,
        status: d.status || 'pending',
        internshipId: d.internshipId || null,
        applicationId: row.internship_id,
        college: d.collegeName || d.educationCollege || null,
        programme: d.className || d.programme || 'Student Internship',
        createdAt: row.created_at,
        uniqueUrl: studentPublicUrl(row.public_id)
      };
    });
    res.set('Cache-Control', 'no-store');
    return res.json({ students });
  } catch (error) {
    console.error('STUDENT ACCOUNTS LIST ERROR:', error);
    return res.status(500).json({ error: 'Student accounts list load नहीं हो सकी।' });
  }
});

// QR destination: a limited public verification/profile page. Never expose Aadhaar or uploaded documents here.
app.get('/api/student/public/:publicId',async(req,res)=>{
  try{
    await studentAccountsTableReady;
    const result=await pool.query('SELECT a.username,a.public_id,a.internship_id,i.data,i.created_at FROM internship_student_accounts a LEFT JOIN internships i ON i.id=a.internship_id WHERE a.public_id=$1 LIMIT 1',[String(req.params.publicId||'')]);
    if(!result.rows.length)return res.status(404).json({error:'Student profile not found'});
    const row=result.rows[0],d=row.data||{};
    const safe={studentName:d.studentName||d.name||row.username,internshipId:d.internshipId||null,status:d.status||'pending',programme:d.className||d.programme||'Student Internship',college:d.collegeName||d.educationCollege||null,university:d.university||null,applicationDate:d.applicationDate||row.created_at,profileUrl:studentPublicUrl(row.public_id)};
    res.set('Cache-Control','no-store');res.json({profile:safe});
  }catch(error){console.error('STUDENT PUBLIC PROFILE ERROR:',error);res.status(500).json({error:'Student profile load नहीं हो सकी।'});}
});


/* =========================================================
   CASHFREE DONATION + RECEIPT + SMS
   Configure Cashfree and MSG91 values in Render Environment.
   ========================================================= */
const CASHFREE_APP_ID = process.env.CASHFREE_APP_ID || '';
const CASHFREE_SECRET_KEY = process.env.CASHFREE_SECRET_KEY || '';
const CASHFREE_MODE = (process.env.CASHFREE_MODE || 'sandbox').toLowerCase();
const CASHFREE_API_VERSION = process.env.CASHFREE_API_VERSION || '2025-01-01';
const DONATION_SITE_URL = (process.env.DONATION_SITE_URL || 'https://nishasevafoundation.org').replace(/\/$/, '');
const MSG91_AUTH_KEY = process.env.MSG91_AUTH_KEY || '';
const MSG91_TEMPLATE_ID = process.env.MSG91_TEMPLATE_ID || '';
const MSG91_SENDER_ID = process.env.MSG91_SENDER_ID || '';
const CASHFREE_BASE = CASHFREE_MODE === 'production' ? 'https://api.cashfree.com/pg' : 'https://sandbox.cashfree.com/pg';
console.log(`[Cashfree] mode=${CASHFREE_MODE}; clientIdConfigured=${Boolean(CASHFREE_APP_ID)}; clientSecretConfigured=${Boolean(CASHFREE_SECRET_KEY)}`);

const donationsTableReady = initializeTable(`CREATE TABLE IF NOT EXISTS donations (
 id BIGSERIAL PRIMARY KEY, order_id VARCHAR(80) UNIQUE NOT NULL, receipt_no VARCHAR(80) UNIQUE NOT NULL,
 donor_name VARCHAR(120) NOT NULL, donor_phone VARCHAR(20) NOT NULL, donor_email VARCHAR(180), amount NUMERIC(12,2) NOT NULL,
 currency VARCHAR(3) NOT NULL DEFAULT 'INR', payment_status VARCHAR(20) NOT NULL DEFAULT 'PENDING', cf_payment_id VARCHAR(100),
 payment_time TIMESTAMPTZ, sms_status VARCHAR(30) NOT NULL DEFAULT 'NOT_SENT', sms_error TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`, 'DONATIONS');


/* ---------------------------------------------------------
   PUBLIC LIVE IMPACT STATISTICS
   Counts are calculated from saved records; no demo numbers.
   --------------------------------------------------------- */
app.get('/api/public-impact-stats', async (req, res) => {
  try {
    await Promise.all([internshipTableReady, donationsTableReady]);
    const [volunteerCount, studentCount, donationTotal] = await Promise.all([
      pool.query('SELECT COUNT(*)::int AS total FROM volunteers'),
      pool.query('SELECT COUNT(*)::int AS total FROM internships'),
      pool.query("SELECT COALESCE(SUM(amount),0)::numeric(14,2) AS total FROM donations WHERE payment_status='PAID'")
    ]);
    const state = await readDB();
    const events = Array.isArray(state.events) ? state.events : [];
    const missions = Array.isArray(state.missions) ? state.missions : [];
    const camps = events.filter(event => {
      const label = [event.title, event.name, event.category, event.type, event.description]
        .filter(Boolean).join(' ').toLowerCase();
      return /\b(camp|health camp|eye camp|medical camp|blood camp)\b/.test(label);
    }).length;
    res.set('Cache-Control', 'no-store');
    return res.json({
      volunteers: Number(volunteerCount.rows[0]?.total || 0),
      students: Number(studentCount.rows[0]?.total || 0),
      donations: Number(donationTotal.rows[0]?.total || 0),
      camps,
      missions: missions.length,
      events: events.length,
      updatedAt: new Date().toISOString()
    });
  } catch (error) {
    console.error('PUBLIC IMPACT STATS ERROR:', error);
    return res.status(503).json({ error: 'Live impact statistics are temporarily unavailable.' });
  }
});

async function cashfreeRequest(url, options={}) {
  if (!CASHFREE_APP_ID || !CASHFREE_SECRET_KEY) throw new Error('Cashfree API credentials are not configured in Hostinger Environment.');
  const response = await fetch(url, { ...options, headers: { 'x-client-id': CASHFREE_APP_ID, 'x-client-secret': CASHFREE_SECRET_KEY, 'x-api-version': CASHFREE_API_VERSION, 'accept':'application/json', 'content-type':'application/json', ...(options.headers||{}) } });
  const data = await response.json().catch(()=>({}));
  if (!response.ok) { console.error('CASHFREE API ERROR', response.status, data); throw new Error(data.message || 'Cashfree API request failed'); }
  return data;
}
function safeText(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function receiptUrl(orderId){return `${PUBLIC_BASE_URL}/api/donations/receipt/${encodeURIComponent(orderId)}`;}
async function sendDonationSms(row){
  if(!MSG91_AUTH_KEY || !MSG91_TEMPLATE_ID){await pool.query("UPDATE donations SET sms_status='NOT_CONFIGURED',sms_error='MSG91 credentials/template not configured',updated_at=NOW() WHERE order_id=$1",[row.order_id]);return;}
  const mobile = String(row.donor_phone).replace(/\D/g,'');
  const payload={template_id:MSG91_TEMPLATE_ID,short_url:'1',recipients:[{mobiles:'91'+mobile,VAR1:row.donor_name,VAR2:String(row.amount),VAR3:row.receipt_no,VAR4:receiptUrl(row.order_id)}]};
  try{
    const resp=await fetch('https://control.msg91.com/api/v5/flow/',{method:'POST',headers:{authkey:MSG91_AUTH_KEY,'content-type':'application/json',accept:'application/json'},body:JSON.stringify(payload)});
    const data=await resp.json().catch(()=>({}));
    if(!resp.ok) throw new Error(data.message||JSON.stringify(data));
    await pool.query("UPDATE donations SET sms_status='SENT_REQUESTED',sms_error=NULL,updated_at=NOW() WHERE order_id=$1",[row.order_id]);
  }catch(e){console.error('DONATION SMS ERROR',e);await pool.query("UPDATE donations SET sms_status='FAILED',sms_error=$2,updated_at=NOW() WHERE order_id=$1",[row.order_id,String(e.message||e).slice(0,1000)]);}
}
async function finalizeDonation(orderId, paymentInfo={}){
  await donationsTableReady;
  const found=await pool.query('SELECT * FROM donations WHERE order_id=$1 LIMIT 1',[orderId]);
  if(!found.rows.length) return null;
  const old=found.rows[0];
  if(old.payment_status==='PAID') return old; // idempotent: never send duplicate SMS

  // Never mark a donation paid from a browser redirect or an unverified webhook alone.
  // Confirm the order directly with Cashfree and compare its amount/currency with our DB.
  const order=await cashfreeRequest(`${CASHFREE_BASE}/orders/${encodeURIComponent(orderId)}`,{method:'GET'});
  const expectedAmount=Math.round(Number(old.amount)*100);
  const cashfreeAmount=Math.round(Number(order.order_amount)*100);
  if(order.order_status!=='PAID' || order.order_currency!=='INR' || !Number.isFinite(cashfreeAmount) || cashfreeAmount!==expectedAmount){
    throw new Error('Cashfree order is not PAID or its amount/currency does not match the donation record.');
  }
  const payment=paymentInfo.payment || paymentInfo;
  if(payment.payment_status && payment.payment_status!=='SUCCESS') throw new Error('Cashfree payment is not successful.');
  if(payment.payment_amount!==undefined && Math.round(Number(payment.payment_amount)*100)!==expectedAmount) {
    throw new Error('Cashfree payment amount does not match the donation record.');
  }
  const paymentId=payment.cf_payment_id || paymentInfo.cf_payment_id || null;

  // Conditional update makes concurrent webhook + status checks idempotent.
  const result=await pool.query(
    "UPDATE donations SET payment_status='PAID',cf_payment_id=COALESCE($2,cf_payment_id),payment_time=COALESCE($3::timestamptz,NOW()),updated_at=NOW() WHERE order_id=$1 AND payment_status<>'PAID' RETURNING *",
    [orderId,paymentId,payment.payment_time||paymentInfo.payment_time||null]
  );
  if(!result.rows.length) {
    const latest=await pool.query('SELECT * FROM donations WHERE order_id=$1 LIMIT 1',[orderId]);
    return latest.rows[0] || null;
  }
  const row=result.rows[0];
  await sendDonationSms(row);
  const refreshed=await pool.query('SELECT * FROM donations WHERE order_id=$1',[orderId]);
  return refreshed.rows[0];
}

app.post('/api/donations/create-order', publicFormLimiter, async(req,res)=>{
 let createdOrderId=null;
 try{
  await donationsTableReady;
  if(!CASHFREE_APP_ID || !CASHFREE_SECRET_KEY) return res.status(503).json({error:'Cashfree credentials are not configured on the server.'});
  if(!['sandbox','production'].includes(CASHFREE_MODE)) return res.status(503).json({error:'CASHFREE_MODE must be sandbox or production.'});
  const name=String(req.body.name||'').trim().slice(0,120), phone=String(req.body.phone||'').replace(/\D/g,''), email=String(req.body.email||'').trim().slice(0,180), amount=Number(req.body.amount);
  if(name.length<2) return res.status(400).json({error:'Please enter donor name.'});
  if(!/^[6-9]\d{9}$/.test(phone)) return res.status(400).json({error:'Enter a valid 10-digit Indian mobile number.'});
  if(!Number.isFinite(amount)||amount<1||amount>1000000||Math.round(amount*100)!==amount*100) return res.status(400).json({error:'Enter a valid donation amount.'});
  if(email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:'Enter a valid email address or leave it blank.'});
  const orderId='NSFDON_'+Date.now()+'_'+crypto.randomBytes(4).toString('hex');
  createdOrderId=orderId;
  const receiptNo='NSF-'+new Date().getFullYear()+'-'+crypto.randomBytes(4).toString('hex').toUpperCase();
  const customerId='donor_'+crypto.randomBytes(8).toString('hex');
  await pool.query('INSERT INTO donations(order_id,receipt_no,donor_name,donor_phone,donor_email,amount) VALUES($1,$2,$3,$4,$5,$6)',[orderId,receiptNo,name,phone,email||null,amount]);
  const created=await cashfreeRequest(`${CASHFREE_BASE}/orders`,{method:'POST',body:JSON.stringify({order_id:orderId,order_amount:amount,order_currency:'INR',customer_details:{customer_id:customerId,customer_name:name,customer_email:email||undefined,customer_phone:phone},order_meta:{return_url:`${DONATION_SITE_URL}/?order_id={order_id}#donate`,notify_url:`${PUBLIC_BASE_URL}/api/donations/webhook`},order_note:'Donation to Nisha Seva Foundation'})});
  res.json({ok:true,orderId,paymentSessionId:created.payment_session_id,mode:CASHFREE_MODE});
 }catch(e){
  console.error('CREATE DONATION ORDER ERROR:',e);
  if(createdOrderId) {
    try { await pool.query("UPDATE donations SET payment_status='FAILED',updated_at=NOW() WHERE order_id=$1 AND payment_status='PENDING'",[createdOrderId]); } catch(dbError) { console.error('DONATION ORDER CLEANUP ERROR:',dbError); }
  }
  res.status(502).json({error:'Could not create Cashfree order. Please try again.'});
 }
});

app.get('/api/donations/status/:orderId',async(req,res)=>{
 try{
  await donationsTableReady;
  const orderId=String(req.params.orderId||'').slice(0,80);
  if(!/^NSFDON_[A-Za-z0-9_]+$/.test(orderId)) return res.status(400).json({error:'Invalid donation order ID.'});
  const local=await pool.query('SELECT * FROM donations WHERE order_id=$1 LIMIT 1',[orderId]);
  if(!local.rows.length)return res.status(404).json({error:'Donation order not found.'});
  let row=local.rows[0];
  if(row.payment_status!=='PAID'){
   const order=await cashfreeRequest(`${CASHFREE_BASE}/orders/${encodeURIComponent(orderId)}`,{method:'GET'});
   if(order.order_status==='PAID'){
    const payments=await cashfreeRequest(`${CASHFREE_BASE}/orders/${encodeURIComponent(orderId)}/payments`,{method:'GET'});
    const paid=(Array.isArray(payments)?payments:[]).find(p=>p.payment_status==='SUCCESS');
    if(paid) row=await finalizeDonation(orderId,paid);
   } else if(['EXPIRED','TERMINATED'].includes(order.order_status)){
    await pool.query("UPDATE donations SET payment_status='FAILED',updated_at=NOW() WHERE order_id=$1 AND payment_status='PENDING'",[orderId]);
   }
  }
  row=(await pool.query('SELECT * FROM donations WHERE order_id=$1',[orderId])).rows[0];
  res.set('Cache-Control','no-store');res.json({orderId,status:row.payment_status,receiptNo:row.payment_status==='PAID'?row.receipt_no:null,receiptUrl:row.payment_status==='PAID'?receiptUrl(orderId):null});
 }catch(e){console.error('DONATION STATUS ERROR:',e);res.status(500).json({error:'Could not verify payment. Please try again shortly.'});}
});

app.post('/api/donations/webhook',async(req,res)=>{
 try{
  const signature=req.headers['x-webhook-signature'], timestamp=req.headers['x-webhook-timestamp'];
  if(!signature||!timestamp||!req.rawBody||!CASHFREE_SECRET_KEY)return res.status(400).send('Missing webhook signature data');
  const expected=crypto.createHmac('sha256',CASHFREE_SECRET_KEY).update(String(timestamp)+req.rawBody.toString('utf8')).digest('base64');
  const a=Buffer.from(String(signature)),b=Buffer.from(expected);
  if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(401).send('Invalid webhook signature');
  const body=req.body||{}, type=body.type||'', orderId=body.data?.order?.order_id, payment=body.data?.payment||{};
  if(orderId && (type==='PAYMENT_SUCCESS_WEBHOOK'||payment.payment_status==='SUCCESS')) await finalizeDonation(orderId,payment);
  if(orderId && (type==='PAYMENT_FAILED_WEBHOOK'||payment.payment_status==='FAILED')) await pool.query("UPDATE donations SET payment_status='FAILED',updated_at=NOW() WHERE order_id=$1 AND payment_status='PENDING'",[orderId]);
  return res.status(200).send('OK');
 }catch(e){console.error('DONATION WEBHOOK ERROR:',e);return res.status(500).send('Webhook processing failed');}
});

app.get('/api/donations/receipt/:orderId',async(req,res)=>{
 try{
  await donationsTableReady;
  const orderId=String(req.params.orderId||'').slice(0,80);
  if(!/^NSFDON_[A-Za-z0-9_]+$/.test(orderId)) return res.status(400).send('Invalid donation order ID.');
  const result=await pool.query('SELECT * FROM donations WHERE order_id=$1 AND payment_status=\'PAID\' LIMIT 1',[orderId]);
  if(!result.rows.length)return res.status(404).send('Verified donation receipt not available yet.');
  const d=result.rows[0];
  res.set('Cache-Control','no-store');res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Donation Receipt ${safeText(d.receipt_no)}</title><style>body{font-family:Arial,sans-serif;background:#eef4f0;padding:20px;color:#173a2d}.receipt{max-width:720px;margin:20px auto;background:white;border:2px solid #16835c;border-radius:18px;padding:34px;box-shadow:0 12px 35px #163a2d1a}.brand{text-align:center;color:#08764f}.rule{border:0;border-top:1px solid #d8e5dd;margin:24px 0}.row{display:flex;justify-content:space-between;gap:20px;padding:10px 0;border-bottom:1px solid #edf1ee}.label{color:#617168}.thanks{text-align:center;line-height:1.6;color:#365449}.actions{text-align:center;margin:18px}.actions button{padding:12px 20px;background:#08764f;color:#fff;border:0;border-radius:8px;font-weight:bold;cursor:pointer}@media print{body{background:white;padding:0}.receipt{box-shadow:none;margin:0 auto;border-radius:0}.actions{display:none}}</style></head><body><main class="receipt"><header class="brand"><h1>NISHA SEVA FOUNDATION</h1><h2>DONATION RECEIPT</h2><p>Thank you for supporting our community work</p></header><hr class="rule"><div class="row"><span class="label">Receipt Number</span><strong>${safeText(d.receipt_no)}</strong></div><div class="row"><span class="label">Donor Name</span><strong>${safeText(d.donor_name)}</strong></div><div class="row"><span class="label">Donation Amount</span><strong>₹${Number(d.amount).toLocaleString('en-IN',{minimumFractionDigits:2,maximumFractionDigits:2})}</strong></div><div class="row"><span class="label">Payment Status</span><strong>SUCCESSFUL</strong></div><div class="row"><span class="label">Payment Date</span><strong>${safeText(new Date(d.payment_time||d.updated_at).toLocaleString('en-IN',{timeZone:'Asia/Kolkata'}))}</strong></div><div class="row"><span class="label">Cashfree Order ID</span><strong>${safeText(d.order_id)}</strong></div><hr class="rule"><p class="thanks">We sincerely thank you for your generous contribution to Nisha Seva Foundation. Your support helps us continue our social service initiatives.<br><strong>With gratitude, Nisha Seva Foundation</strong></p><div class="actions"><button onclick="window.print()">Download / Print Receipt (Save as PDF)</button></div></main></body></html>`);
 }catch(e){console.error('DONATION RECEIPT ERROR:',e);res.status(500).send('Receipt could not be generated.');}
});

app.get('/api/admin/donations',requireAdmin,async(req,res)=>{
 try{await donationsTableReady;const r=await pool.query('SELECT order_id,receipt_no,donor_name,donor_phone,donor_email,amount,currency,payment_status,payment_time,sms_status,sms_error,created_at FROM donations ORDER BY created_at DESC LIMIT 500');res.json({donations:r.rows});}
 catch(e){console.error('ADMIN DONATIONS ERROR:',e);res.status(500).json({error:'Could not load donation records.'});}
});

/* =========================================================
   COMMUNITY HELP DESK — Phase 03/04
   ========================================================= */
const communityRequestsTableReady = initializeTable(`
  CREATE TABLE IF NOT EXISTS community_help_requests (
    id BIGSERIAL PRIMARY KEY,
    reference_id VARCHAR(32) UNIQUE NOT NULL,
    name VARCHAR(90) NOT NULL,
    phone VARCHAR(18) NOT NULL,
    request_type VARCHAR(32) NOT NULL,
    area VARCHAR(100),
    details TEXT NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`, 'COMMUNITY REQUESTS');

app.post('/api/community-requests', publicFormLimiter, async (req, res) => {
  try {
    await communityRequestsTableReady;
    const body = req.body || {};
    const name = String(body.name || '').trim().slice(0, 90);
    const phone = String(body.phone || '').trim().slice(0, 18);
    const requestType = String(body.requestType || '').trim();
    const area = String(body.area || '').trim().slice(0, 100);
    const details = String(body.details || '').trim().slice(0, 1200);
    const allowed = new Set(['help','volunteer','skill','opportunity','suggestion']);
    if (!name || name.length < 2) return res.status(400).json({ error: 'कृपया सही नाम भरें।' });
    if (!/^[0-9+()\-\s]{8,18}$/.test(phone)) return res.status(400).json({ error: 'कृपया सही मोबाइल नंबर भरें।' });
    if (!allowed.has(requestType)) return res.status(400).json({ error: 'कृपया अनुरोध का प्रकार चुनें।' });
    if (details.length < 10) return res.status(400).json({ error: 'कृपया कम से कम 10 अक्षरों में विवरण लिखें।' });
    const referenceId = 'NSF-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(3).toString('hex').toUpperCase();
    await pool.query(
      `INSERT INTO community_help_requests (reference_id,name,phone,request_type,area,details) VALUES ($1,$2,$3,$4,$5,$6)`,
      [referenceId,name,phone,requestType,area,details]
    );
    return res.status(201).json({ success: true, referenceId, message: 'Request received' });
  } catch (error) {
    console.error('COMMUNITY REQUEST SAVE ERROR:', error);
    return res.status(500).json({ error: 'अनुरोध सेव नहीं हो पाया। कृपया थोड़ी देर बाद फिर कोशिश करें।' });
  }
});

app.get('/api/community-requests', requireAdmin, async (req, res) => {
  try {
    await communityRequestsTableReady;
    const result = await pool.query(`SELECT id,reference_id,name,phone,request_type,area,details,status,created_at FROM community_help_requests ORDER BY created_at DESC LIMIT 500`);
    res.set('Cache-Control', 'no-store');
    return res.json({ requests: result.rows });
  } catch (error) {
    console.error('COMMUNITY REQUEST LIST ERROR:', error);
    return res.status(500).json({ error: 'Community requests load नहीं हो सके।' });
  }
});


/* =========================================================
   NSF TREASURER / FINANCE MANAGEMENT MODULE
   Additive schema only: existing app-state and donation data are preserved.
   ========================================================= */
function financeSession(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const session = token && sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    if (token) sessions.delete(token);
    return res.status(401).json({ error: 'Unauthorized. Please login again.' });
  }
  if (!['admin', 'treasurer'].includes(session.role)) {
    return res.status(403).json({ error: 'Finance access denied.' });
  }
  req.userRole = session.role;
  req.financeToken = token;
  next();
}
function financeAdmin(req, res, next) {
  if (req.userRole !== 'admin') return res.status(403).json({ error: 'Only Admin/President can approve or manage this action.' });
  next();
}
function financeAudit(req, action, entityType, entityId, details={}) {
  return pool.query(
    `INSERT INTO nsf_finance_audit_logs(actor_role, action, entity_type, entity_id, details)
     VALUES($1,$2,$3,$4,$5::jsonb)`,
    [req.userRole || 'system', String(action).slice(0,80), String(entityType).slice(0,80),
     entityId == null ? null : String(entityId).slice(0,100), JSON.stringify(details || {})]
  );
}
function financeAmount(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0 || n > 100000000 || Math.round(n * 100) !== n * 100) return null;
  return n.toFixed(2);
}
function financeDate(value) {
  const s = String(value || '').slice(0,10);
  return /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s)) ? s : null;
}

const financeTablesReady = (async () => {
  await initializeTable(`
    CREATE TABLE IF NOT EXISTS nsf_finance_accounts (
      id BIGSERIAL PRIMARY KEY,
      account_name VARCHAR(100) NOT NULL,
      account_type VARCHAR(24) NOT NULL CHECK (account_type IN ('CASH','BANK','UPI','ONLINE_CLEARING','OTHER')),
      bank_name VARCHAR(100), account_last4 VARCHAR(4),
      opening_balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_by VARCHAR(24) NOT NULL DEFAULT 'admin',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS nsf_finance_income (
      id BIGSERIAL PRIMARY KEY,
      receipt_no VARCHAR(50) UNIQUE NOT NULL,
      source VARCHAR(40) NOT NULL,
      payer_name VARCHAR(140) NOT NULL,
      category VARCHAR(60) NOT NULL,
      amount NUMERIC(14,2) NOT NULL CHECK (amount > 0),
      income_date DATE NOT NULL,
      payment_mode VARCHAR(24) NOT NULL,
      account_id BIGINT REFERENCES nsf_finance_accounts(id),
      reference_no VARCHAR(120),
      notes TEXT,
      created_by VARCHAR(24) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS nsf_finance_expenses (
      id BIGSERIAL PRIMARY KEY,
      expense_no VARCHAR(50) UNIQUE NOT NULL,
      vendor_name VARCHAR(140) NOT NULL,
      category VARCHAR(60) NOT NULL,
      amount NUMERIC(14,2) NOT NULL CHECK (amount > 0),
      expense_date DATE NOT NULL,
      description TEXT NOT NULL,
      account_id BIGINT REFERENCES nsf_finance_accounts(id),
      payment_mode VARCHAR(24),
      payment_reference VARCHAR(120),
      bill_path TEXT,
      status VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','APPROVED','REJECTED','PAID')),
      requested_by VARCHAR(24) NOT NULL,
      approved_by VARCHAR(24), approved_at TIMESTAMPTZ, admin_note TEXT,
      paid_by VARCHAR(24), paid_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS nsf_finance_bank_lines (
      id BIGSERIAL PRIMARY KEY,
      statement_date DATE NOT NULL,
      description TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      reference_no VARCHAR(140),
      status VARCHAR(20) NOT NULL DEFAULT 'UNMATCHED' CHECK (status IN ('UNMATCHED','MATCHED','IGNORED')),
      matched_type VARCHAR(20), matched_id BIGINT,
      imported_by VARCHAR(24) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS nsf_finance_audit_logs (
      id BIGSERIAL PRIMARY KEY,
      actor_role VARCHAR(24) NOT NULL,
      action VARCHAR(80) NOT NULL,
      entity_type VARCHAR(80) NOT NULL,
      entity_id VARCHAR(100),
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS nsf_finance_income_date_idx ON nsf_finance_income(income_date DESC);
    CREATE INDEX IF NOT EXISTS nsf_finance_expenses_status_idx ON nsf_finance_expenses(status, expense_date DESC);
    CREATE INDEX IF NOT EXISTS nsf_finance_bank_lines_status_idx ON nsf_finance_bank_lines(status, statement_date DESC);
    CREATE INDEX IF NOT EXISTS nsf_finance_audit_created_idx ON nsf_finance_audit_logs(created_at DESC);
  `, 'NSF_FINANCE');
  await pool.query(`ALTER TABLE nsf_finance_expenses ADD COLUMN IF NOT EXISTS payment_proof_path TEXT`);
  await pool.query(`
    INSERT INTO nsf_finance_accounts(account_name, account_type, created_by)
    SELECT 'Cash in Hand','CASH','system'
    WHERE NOT EXISTS (SELECT 1 FROM nsf_finance_accounts WHERE account_name='Cash in Hand');
    INSERT INTO nsf_finance_accounts(account_name, account_type, created_by)
    SELECT 'Online Donations Clearing','ONLINE_CLEARING','system'
    WHERE NOT EXISTS (SELECT 1 FROM nsf_finance_accounts WHERE account_name='Online Donations Clearing');
  `);
})();

const financeUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['application/pdf','image/jpeg','image/png','image/webp'];
    cb(allowed.includes(file.mimetype) ? null : new Error('Only PDF, JPG, PNG and WEBP documents are allowed.'), allowed.includes(file.mimetype));
  }
});

app.get('/api/finance/summary', financeSession, async (req,res) => {
  try {
    await Promise.all([financeTablesReady, donationsTableReady]);
    const [donations, income, expenses, pending, accounts] = await Promise.all([
      pool.query("SELECT COALESCE(SUM(amount),0)::numeric(14,2) AS total, COUNT(*)::int AS count FROM donations WHERE payment_status='PAID'"),
      pool.query('SELECT COALESCE(SUM(amount),0)::numeric(14,2) AS total, COUNT(*)::int AS count FROM nsf_finance_income'),
      pool.query("SELECT COALESCE(SUM(amount),0)::numeric(14,2) AS total, COUNT(*)::int AS count FROM nsf_finance_expenses WHERE status='PAID'"),
      pool.query("SELECT COUNT(*)::int AS count, COALESCE(SUM(amount),0)::numeric(14,2) AS total FROM nsf_finance_expenses WHERE status='PENDING'"),
      pool.query('SELECT COALESCE(SUM(opening_balance),0)::numeric(14,2) AS opening FROM nsf_finance_accounts')
    ]);
    const d=donations.rows[0], i=income.rows[0], e=expenses.rows[0], p=pending.rows[0];
    const gross=Number(d.total)+Number(i.total);
    return res.set('Cache-Control','no-store').json({
      donations:{total:Number(d.total),count:d.count},
      otherIncome:{total:Number(i.total),count:i.count},
      paidExpenses:{total:Number(e.total),count:e.count},
      pendingExpenses:{total:Number(p.total),count:p.count},
      bookBalance:Number(accounts.rows[0].opening)+gross-Number(e.total),
      totalIncome:gross, currency:'INR'
    });
  } catch(e) { console.error('FINANCE SUMMARY ERROR:',e); return res.status(500).json({error:'Finance summary could not be loaded.'}); }
});

app.get('/api/finance/donations', financeSession, async (req,res) => {
  try {
    await donationsTableReady;
    const r=await pool.query(`SELECT order_id,receipt_no,donor_name,donor_phone,donor_email,amount,currency,payment_status,payment_time,sms_status,created_at
      FROM donations ORDER BY created_at DESC LIMIT 1000`);
    return res.set('Cache-Control','no-store').json({donations:r.rows});
  } catch(e) { console.error('FINANCE DONATIONS ERROR:',e); return res.status(500).json({error:'Donation records could not be loaded.'}); }
});

app.get('/api/finance/income', financeSession, async (req,res) => {
  try {
    await financeTablesReady;
    const r=await pool.query(`SELECT i.*,a.account_name FROM nsf_finance_income i LEFT JOIN nsf_finance_accounts a ON a.id=i.account_id ORDER BY i.income_date DESC,i.id DESC LIMIT 1000`);
    return res.set('Cache-Control','no-store').json({income:r.rows});
  } catch(e) { console.error('FINANCE INCOME LIST ERROR:',e); return res.status(500).json({error:'Income records could not be loaded.'}); }
});

app.post('/api/finance/income', financeSession, async (req,res) => {
  try {
    await financeTablesReady;
    const b=req.body||{}, amount=financeAmount(b.amount), date=financeDate(b.incomeDate);
    const payer=String(b.payerName||'').trim().slice(0,140), category=String(b.category||'').trim().slice(0,60);
    const modes=['CASH','BANK_TRANSFER','UPI','CHEQUE','OTHER'];
    if(!amount||!date||payer.length<2||!category||!modes.includes(b.paymentMode)) return res.status(400).json({error:'Valid payer, category, amount, date and payment mode are required.'});
    if(b.accountId && !/^\d+$/.test(String(b.accountId))) return res.status(400).json({error:'Invalid account.'});
    if(b.accountId) {
      const account=(await pool.query('SELECT id FROM nsf_finance_accounts WHERE id=$1 AND active=true',[b.accountId])).rows[0];
      if(!account) return res.status(400).json({error:'Selected finance account is inactive or unavailable.'});
    }
    const receiptNo='NSF-INC-'+new Date().getFullYear()+'-'+crypto.randomBytes(4).toString('hex').toUpperCase();
    const r=await pool.query(`INSERT INTO nsf_finance_income(receipt_no,source,payer_name,category,amount,income_date,payment_mode,account_id,reference_no,notes,created_by)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [receiptNo,String(b.source||'OFFLINE').slice(0,40),payer,category,amount,date,b.paymentMode,b.accountId||null,String(b.referenceNo||'').slice(0,120)||null,String(b.notes||'').slice(0,2000)||null,req.userRole]);
    await financeAudit(req,'INCOME_CREATED','income',r.rows[0].id,{amount,receiptNo});
    return res.status(201).json({income:r.rows[0]});
  } catch(e) { console.error('FINANCE INCOME CREATE ERROR:',e); return res.status(500).json({error:'Income record could not be saved.'}); }
});

app.get('/api/finance/income/:id/receipt', financeSession, async (req,res) => {
  try {
    await financeTablesReady;
    const r=await pool.query('SELECT i.*,a.account_name FROM nsf_finance_income i LEFT JOIN nsf_finance_accounts a ON a.id=i.account_id WHERE i.id=$1',[req.params.id]);
    if(!r.rows.length) return res.status(404).send('Receipt not found.');
    const x=r.rows[0], fmt=Number(x.amount).toLocaleString('en-IN',{minimumFractionDigits:2,maximumFractionDigits:2});
    const html=`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${safeText(x.receipt_no)}</title><style>body{font-family:Arial;background:#eef5f1;padding:20px;color:#17372c}.paper{max-width:720px;margin:20px auto;background:white;border:2px solid #16845e;border-radius:18px;padding:34px}.brand{text-align:center;color:#08764f}.line{display:flex;justify-content:space-between;border-bottom:1px solid #e5eee9;padding:12px 0;gap:20px}.print{text-align:center;margin:20px}.print button{background:#08764f;color:white;padding:12px 20px;border:0;border-radius:10px}@media print{body{background:white}.paper{margin:0 auto;box-shadow:none}.print{display:none}}</style></head><body><main class="paper"><header class="brand"><h1>NISHA SEVA FOUNDATION</h1><h2>INCOME RECEIPT</h2></header><div class="line"><span>Receipt No.</span><b>${safeText(x.receipt_no)}</b></div><div class="line"><span>Received From</span><b>${safeText(x.payer_name)}</b></div><div class="line"><span>Category</span><b>${safeText(x.category)}</b></div><div class="line"><span>Amount</span><b>₹${fmt}</b></div><div class="line"><span>Date</span><b>${safeText(x.income_date)}</b></div><div class="line"><span>Payment Mode</span><b>${safeText(x.payment_mode)}</b></div><div class="line"><span>Reference</span><b>${safeText(x.reference_no||'-')}</b></div><p style="text-align:center;margin-top:28px">Thank you for supporting Nisha Seva Foundation.</p><div class="print"><button onclick="window.print()">Print / Save PDF</button></div></main></body></html>`;
    return res.set('Cache-Control','no-store').type('html').send(html);
  } catch(e) { console.error('FINANCE RECEIPT ERROR:',e); return res.status(500).send('Receipt could not be generated.'); }
});

app.get('/api/finance/expenses', financeSession, async (req,res) => {
  try {
    await financeTablesReady;
    const r=await pool.query(`SELECT e.*,a.account_name FROM nsf_finance_expenses e LEFT JOIN nsf_finance_accounts a ON a.id=e.account_id ORDER BY e.expense_date DESC,e.id DESC LIMIT 1000`);
    return res.set('Cache-Control','no-store').json({expenses:r.rows});
  } catch(e) { console.error('FINANCE EXPENSE LIST ERROR:',e); return res.status(500).json({error:'Expense records could not be loaded.'}); }
});

app.post('/api/finance/attachments', financeSession, financeUpload.single('file'), async (req,res) => {
  try {
    if(!req.file) return res.status(400).json({error:'Please choose a PDF or image bill.'});
    const bucket='finance-private';
    const created=await supabase.storage.createBucket(bucket,{public:false,fileSizeLimit:8*1024*1024,allowedMimeTypes:['application/pdf','image/jpeg','image/png','image/webp']});
    if(created.error && !/already exists|duplicate/i.test(created.error.message||'')) {
      const check=await supabase.storage.getBucket(bucket);
      if(check.error) throw created.error;
    }
    const ext=path.extname(req.file.originalname||'').toLowerCase().replace(/[^.a-z0-9]/g,'').slice(0,10) || (req.file.mimetype==='application/pdf'?'.pdf':'.img');
    const objectPath=`expense-bills/${Date.now()}-${crypto.randomUUID()}${ext}`;
    const uploaded=await supabase.storage.from(bucket).upload(objectPath,req.file.buffer,{contentType:req.file.mimetype,upsert:false});
    if(uploaded.error) throw uploaded.error;
    await financeAudit(req,'BILL_UPLOADED','attachment',objectPath,{mimeType:req.file.mimetype,size:req.file.size});
    return res.status(201).json({ok:true,billPath:objectPath});
  } catch(e) { console.error('FINANCE BILL UPLOAD ERROR:',e); return res.status(500).json({error:'Bill upload failed. Check private Supabase Storage bucket permissions.'}); }
});

app.get('/api/finance/attachments/:id', financeSession, async (req,res) => {
  try {
    const objectPath=String(req.params.id||'').replace(/^\/+/,'');
    if(!objectPath.startsWith('expense-bills/')) return res.status(400).json({error:'Invalid attachment path.'});
    const signed=await supabase.storage.from('finance-private').createSignedUrl(objectPath,60);
    if(signed.error) throw signed.error;
    return res.json({url:signed.data.signedUrl,expiresIn:60});
  } catch(e) { console.error('FINANCE BILL SIGN ERROR:',e); return res.status(404).json({error:'Bill document could not be opened.'}); }
});

app.post('/api/finance/expenses', financeSession, async (req,res) => {
  try {
    await financeTablesReady;
    const b=req.body||{}, amount=financeAmount(b.amount), date=financeDate(b.expenseDate);
    const vendor=String(b.vendorName||'').trim().slice(0,140), category=String(b.category||'').trim().slice(0,60), desc=String(b.description||'').trim().slice(0,3000);
    if(!amount||!date||vendor.length<2||!category||desc.length<4) return res.status(400).json({error:'Vendor, category, description, valid amount and date are required.'});
    if(b.billPath && !String(b.billPath).startsWith('expense-bills/')) return res.status(400).json({error:'Invalid bill attachment.'});
    if(b.accountId && !/^\d+$/.test(String(b.accountId))) return res.status(400).json({error:'Invalid finance account.'});
    if(b.accountId) {
      const account=(await pool.query('SELECT id FROM nsf_finance_accounts WHERE id=$1 AND active=true',[b.accountId])).rows[0];
      if(!account) return res.status(400).json({error:'Selected finance account is inactive or unavailable.'});
    }
    const expenseNo='NSF-EXP-'+new Date().getFullYear()+'-'+crypto.randomBytes(4).toString('hex').toUpperCase();
    const r=await pool.query(`INSERT INTO nsf_finance_expenses(expense_no,vendor_name,category,amount,expense_date,description,account_id,bill_path,requested_by)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [expenseNo,vendor,category,amount,date,desc,b.accountId||null,b.billPath||null,req.userRole]);
    await financeAudit(req,'EXPENSE_SUBMITTED','expense',r.rows[0].id,{amount,expenseNo});
    return res.status(201).json({expense:r.rows[0]});
  } catch(e) { console.error('FINANCE EXPENSE CREATE ERROR:',e); return res.status(500).json({error:'Expense request could not be saved.'}); }
});

app.post('/api/finance/expenses/:id/decision', financeSession, financeAdmin, async (req,res) => {
  const client=await pool.connect();
  try {
    await financeTablesReady;
    const decision=String(req.body?.decision||'').toUpperCase(), note=String(req.body?.note||'').trim().slice(0,1000);
    if(!['APPROVE','REJECT'].includes(decision)) return res.status(400).json({error:'Decision must be APPROVE or REJECT.'});
    if(decision==='REJECT' && !note) return res.status(400).json({error:'A rejection reason is required.'});
    await client.query('BEGIN');
    const r=await client.query('UPDATE nsf_finance_expenses SET status=$2,approved_by=$3,approved_at=NOW(),admin_note=$4,updated_at=NOW() WHERE id=$1 AND status=$5 RETURNING *',
      [req.params.id,decision==='APPROVE'?'APPROVED':'REJECTED','admin',note||null,'PENDING']);
    if(!r.rows.length){await client.query('ROLLBACK');return res.status(409).json({error:'Expense is no longer pending or was not found.'});}
    await client.query('INSERT INTO nsf_finance_audit_logs(actor_role,action,entity_type,entity_id,details) VALUES($1,$2,$3,$4,$5::jsonb)',
      ['admin',`EXPENSE_${decision} `,'expense',String(req.params.id),JSON.stringify({note,amount:r.rows[0].amount})]);
    await client.query('COMMIT');
    return res.json({expense:r.rows[0]});
  } catch(e) { try{await client.query('ROLLBACK');}catch{} console.error('FINANCE EXPENSE DECISION ERROR:',e); return res.status(500).json({error:'Expense decision could not be saved.'}); }
  finally {client.release();}
});

app.post('/api/finance/expenses/:id/mark-paid', financeSession, async (req,res) => {
  try {
    await financeTablesReady;
    const b=req.body||{}, mode=String(b.paymentMode||'').toUpperCase();
    if(!['CASH','BANK_TRANSFER','UPI','CHEQUE','OTHER'].includes(mode)) return res.status(400).json({error:'Select a valid payment mode.'});
    const ref=String(b.paymentReference||'').trim().slice(0,120);
    const proof=String(b.paymentProofPath||'');
    if(!ref) return res.status(400).json({error:'Payment reference / transaction ID is required.'});
    if(proof && !proof.startsWith('expense-bills/')) return res.status(400).json({error:'Invalid payment proof attachment.'});
    const r=await pool.query(`UPDATE nsf_finance_expenses SET status='PAID',payment_mode=$2,payment_reference=$3,payment_proof_path=$4,paid_by=$5,paid_at=NOW(),updated_at=NOW()
      WHERE id=$1 AND status='APPROVED' RETURNING *`,[req.params.id,mode,ref,proof||null,req.userRole]);
    if(!r.rows.length) return res.status(409).json({error:'Only an approved expense can be marked paid.'});
    await financeAudit(req,'EXPENSE_MARKED_PAID','expense',r.rows[0].id,{amount:r.rows[0].amount,reference:ref});
    return res.json({expense:r.rows[0]});
  } catch(e) { console.error('FINANCE EXPENSE PAID ERROR:',e); return res.status(500).json({error:'Payment status could not be updated.'}); }
});

app.get('/api/finance/accounts', financeSession, async (req,res) => {
  try { await financeTablesReady; const r=await pool.query('SELECT id,account_name,account_type,bank_name,account_last4,opening_balance,active,created_at FROM nsf_finance_accounts ORDER BY id'); return res.json({accounts:r.rows}); }
  catch(e){console.error('FINANCE ACCOUNTS ERROR:',e);return res.status(500).json({error:'Accounts could not be loaded.'});}
});
app.post('/api/finance/accounts', financeSession, financeAdmin, async (req,res) => {
  try {
    await financeTablesReady;
    const b=req.body||{}, name=String(b.accountName||'').trim().slice(0,100), type=String(b.accountType||'').toUpperCase();
    const allowed=['CASH','BANK','UPI','ONLINE_CLEARING','OTHER'];
    const opening=Number(b.openingBalance||0);
    if(name.length<2||!allowed.includes(type)||!Number.isFinite(opening)||opening<0||opening>100000000) return res.status(400).json({error:'Valid account name, type and opening balance are required.'});
    const last4=String(b.accountLast4||'').replace(/\D/g,'').slice(-4);
    const r=await pool.query('INSERT INTO nsf_finance_accounts(account_name,account_type,bank_name,account_last4,opening_balance,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,account_name,account_type,bank_name,account_last4,opening_balance,active',
      [name,type,String(b.bankName||'').slice(0,100)||null,last4||null,opening,req.userRole]);
    await financeAudit(req,'ACCOUNT_CREATED','account',r.rows[0].id,{accountName:name,type});
    return res.status(201).json({account:r.rows[0]});
  } catch(e){console.error('FINANCE ACCOUNT CREATE ERROR:',e);return res.status(500).json({error:'Account could not be created.'});}
});

app.post('/api/finance/accounts/:id/toggle', financeSession, financeAdmin, async (req,res) => {
  try {
    await financeTablesReady;
    const r=await pool.query('UPDATE nsf_finance_accounts SET active=NOT active,updated_at=NOW() WHERE id=$1 RETURNING id,account_name,active',[req.params.id]);
    if(!r.rows.length)return res.status(404).json({error:'Account not found.'});
    await financeAudit(req,'ACCOUNT_STATUS_CHANGED','account',req.params.id,{active:r.rows[0].active});
    return res.json({account:r.rows[0]});
  } catch(e){console.error('FINANCE ACCOUNT STATUS ERROR:',e);return res.status(500).json({error:'Account status could not be changed.'});}
});

app.get('/api/finance/ledger', financeSession, async (req,res) => {
  try {
    await Promise.all([financeTablesReady,donationsTableReady]);
    const r=await pool.query(`
      SELECT * FROM (
        SELECT 'DONATION'::text AS entry_type, d.id::text AS entry_id, d.receipt_no AS reference_no,
          d.donor_name AS party, 'Donation'::text AS category, d.amount::numeric(14,2) AS amount,
          'INCOME'::text AS direction, COALESCE(d.payment_time,d.created_at)::date AS entry_date,
          d.payment_status AS status, d.order_id AS note
        FROM donations d WHERE d.payment_status='PAID'
        UNION ALL
        SELECT 'OTHER_INCOME', i.id::text, i.receipt_no, i.payer_name, i.category, i.amount,
          'INCOME', i.income_date, 'RECEIVED', COALESCE(i.reference_no,i.notes,'')
        FROM nsf_finance_income i
        UNION ALL
        SELECT 'EXPENSE', e.id::text, e.expense_no, e.vendor_name, e.category, e.amount,
          'EXPENSE', e.expense_date, e.status, COALESCE(e.payment_reference,e.description)
        FROM nsf_finance_expenses e WHERE e.status='PAID'
      ) ledger ORDER BY entry_date DESC LIMIT 2000`);
    return res.set('Cache-Control','no-store').json({entries:r.rows});
  } catch(e){console.error('FINANCE LEDGER ERROR:',e);return res.status(500).json({error:'Ledger could not be loaded.'});}
});

app.get('/api/finance/reports', financeSession, async (req,res) => {
  try {
    await Promise.all([financeTablesReady,donationsTableReady]);
    const from=financeDate(req.query.from)||'2000-01-01', to=financeDate(req.query.to)||'2099-12-31';
    const r=await pool.query(`
      SELECT category, direction, COUNT(*)::int AS count, COALESCE(SUM(amount),0)::numeric(14,2) AS total
      FROM (
        SELECT 'Donation'::text AS category,'INCOME'::text AS direction,amount,COALESCE(payment_time,created_at)::date AS d FROM donations WHERE payment_status='PAID'
        UNION ALL SELECT category,'INCOME',amount,income_date FROM nsf_finance_income
        UNION ALL SELECT category,'EXPENSE',amount,expense_date FROM nsf_finance_expenses WHERE status='PAID'
      ) x WHERE d BETWEEN $1::date AND $2::date GROUP BY category,direction ORDER BY direction,category`,[from,to]);
    return res.json({from,to,rows:r.rows});
  } catch(e){console.error('FINANCE REPORT ERROR:',e);return res.status(500).json({error:'Financial report could not be generated.'});}
});

app.get('/api/finance/bank-lines', financeSession, async (req,res) => {
  try {await financeTablesReady;const r=await pool.query('SELECT * FROM nsf_finance_bank_lines ORDER BY statement_date DESC,id DESC LIMIT 2000');return res.json({lines:r.rows});}
  catch(e){console.error('FINANCE BANK LINES ERROR:',e);return res.status(500).json({error:'Bank statement records could not be loaded.'});}
});
app.post('/api/finance/bank-lines/import', financeSession, async (req,res) => {
  const client=await pool.connect();
  try {
    await financeTablesReady;
    const rows=Array.isArray(req.body?.rows)?req.body.rows:[];
    if(!rows.length||rows.length>2000) return res.status(400).json({error:'Upload between 1 and 2,000 statement rows.'});
    await client.query('BEGIN');
    let count=0;
    for(const row of rows){
      const date=financeDate(row.date), amount=Number(row.amount), description=String(row.description||'').trim().slice(0,1000);
      if(!date||!Number.isFinite(amount)||amount===0||Math.abs(amount)>100000000||!description) continue;
      await client.query('INSERT INTO nsf_finance_bank_lines(statement_date,description,amount,reference_no,imported_by) VALUES($1,$2,$3,$4,$5)',
        [date,description,amount,String(row.reference||'').slice(0,140)||null,req.userRole]);
      count++;
    }
    await client.query('COMMIT');
    await financeAudit(req,'BANK_STATEMENT_IMPORTED','bank_statement',null,{rows:count});
    return res.status(201).json({ok:true,imported:count});
  } catch(e){try{await client.query('ROLLBACK');}catch{}console.error('FINANCE BANK IMPORT ERROR:',e);return res.status(500).json({error:'Bank statement could not be imported.'});}
  finally{client.release();}
});
app.post('/api/finance/bank-lines/:id/match', financeSession, async (req,res) => {
  try {
    await financeTablesReady;
    const b=req.body||{}, type=String(b.entryType||'').toUpperCase(), id=Number(b.entryId);
    if(!['DONATION','OTHER_INCOME','EXPENSE'].includes(type)||!Number.isSafeInteger(id)||id<1) return res.status(400).json({error:'Select a valid ledger entry.'});
    const line=(await pool.query('SELECT * FROM nsf_finance_bank_lines WHERE id=$1 AND status=\'UNMATCHED\'',[req.params.id])).rows[0];
    if(!line) return res.status(404).json({error:'Unmatched bank line not found.'});
    let actual;
    if(type==='DONATION') actual=(await pool.query("SELECT amount FROM donations WHERE id=$1 AND payment_status='PAID'",[id])).rows[0]?.amount;
    if(type==='OTHER_INCOME') actual=(await pool.query('SELECT amount FROM nsf_finance_income WHERE id=$1',[id])).rows[0]?.amount;
    if(type==='EXPENSE') actual=(await pool.query("SELECT amount FROM nsf_finance_expenses WHERE id=$1 AND status='PAID'",[id])).rows[0]?.amount;
    if(actual===undefined||Math.round(Number(actual)*100)!==Math.round(Math.abs(Number(line.amount))*100)) return res.status(409).json({error:'Bank line amount does not match the selected paid ledger entry.'});
    const expectedDirection=type==='EXPENSE'?'debit':'credit';
    const description=String(line.description||'').toLowerCase();
    if((Number(line.amount)<0)!==(expectedDirection==='debit')) return res.status(409).json({error:'Bank line direction does not match the selected ledger entry.'});
    const r=await pool.query("UPDATE nsf_finance_bank_lines SET status='MATCHED',matched_type=$2,matched_id=$3 WHERE id=$1 AND status='UNMATCHED' RETURNING *",[req.params.id,type,id]);
    if(!r.rows.length)return res.status(409).json({error:'Bank line was matched by another request.'});
    await financeAudit(req,'BANK_LINE_MATCHED','bank_line',req.params.id,{entryType:type,entryId:id});
    return res.json({line:r.rows[0]});
  } catch(e){console.error('FINANCE BANK MATCH ERROR:',e);return res.status(500).json({error:'Bank line could not be matched.'});}
});
app.post('/api/finance/bank-lines/:id/ignore', financeSession, financeAdmin, async (req,res) => {
  try {const r=await pool.query("UPDATE nsf_finance_bank_lines SET status='IGNORED' WHERE id=$1 AND status='UNMATCHED' RETURNING *",[req.params.id]);if(!r.rows.length)return res.status(404).json({error:'Unmatched bank line not found.'});await financeAudit(req,'BANK_LINE_IGNORED','bank_line',req.params.id,{});return res.json({line:r.rows[0]});}
  catch(e){console.error('FINANCE BANK IGNORE ERROR:',e);return res.status(500).json({error:'Bank line could not be ignored.'});}
});

app.get('/api/finance/audit', financeSession, async (req,res) => {
  try {await financeTablesReady;const r=await pool.query('SELECT id,actor_role,action,entity_type,entity_id,details,created_at FROM nsf_finance_audit_logs ORDER BY created_at DESC LIMIT 500');return res.json({logs:r.rows});}
  catch(e){console.error('FINANCE AUDIT ERROR:',e);return res.status(500).json({error:'Audit history could not be loaded.'});}
});

/* =========================================================
   START SERVER
   ========================================================= */

// Hostinger expects the HTTP listener to start immediately. Do not wait for
// Supabase/PostgreSQL DDL or schema initialization before calling listen().
const server = app.listen(PORT, () => {
  console.log('======================================');
  console.log('Nisha Seva backend running');
  console.log(`Port: ${PORT}`);
  console.log('Admin panel: /admin');
  console.log(`Volunteer verification: ${PUBLIC_BASE_URL}/verify/volunteer/<code>`);
  console.log('Student internship API: /api/internships');
  console.log('======================================');
});

// Database schema initialization continues in the background. Routes that
// depend on a schema already await their corresponding *Ready promise.
Promise.all([
  secretaryTableReady,
  internshipTableReady,
  projectSubmissionTableReady,
  studentAccountsTableReady,
  passwordResetTableReady,
  donationsTableReady,
  communityRequestsTableReady,
  financeTablesReady
]).then(() => {
  console.log('[STARTUP] Database schema initialization completed.');
}).catch((error) => {
  // Keep the HTTP process alive so Hostinger does not restart-loop the app.
  // The affected database-backed routes will report their own errors.
  console.error('[STARTUP] Database schema initialization failed:', error.message || error);
});

server.on('error', (error) => {
  console.error('[SERVER LISTEN ERROR]:', error);
});
