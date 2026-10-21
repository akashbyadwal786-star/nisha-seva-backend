require('dotenv').config();

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const {
  readDB,
  writeDB,
  nextId,
  pool
} = require('./db');

const {
  createClient
} = require('@supabase/supabase-js');


/* =========================================================
   SUPABASE
   ========================================================= */

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);


/* =========================================================
   APP CONFIG
   ========================================================= */

const app = express();

const PORT =
  process.env.PORT || 4000;

const ADMIN_USERNAME =
  process.env.ADMIN_USERNAME || 'admin';

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD ||
  'change-this-password';

// Set both values in Render Environment for a separate coordinator account.
const COORDINATOR_USERNAME = process.env.COORDINATOR_USERNAME || '';
const COORDINATOR_PASSWORD = process.env.COORDINATOR_PASSWORD || '';

const PUBLIC_BASE_URL =
  process.env.PUBLIC_BASE_URL ||
  'https://nisha-seva-backend.onrender.com';


/* =========================================================
   MIDDLEWARE
   ========================================================= */

app.use(cors());

app.use(
  express.json({
    limit: '30mb'
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
  if (session.role === 'coordinator' && !(/^\/api\/internships(?:\/|$)/.test(req.path) || req.path === '/api/admin/logout' || req.path === '/api/student/accounts')) {
    return res.status(403).json({ error: 'Forbidden: coordinator access is limited to internship management' });
  }

  if (!['admin','coordinator'].includes(session.role)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  req.userRole = session.role;
  next();
}


/* =========================================================
   ADMIN LOGIN
   ========================================================= */

app.post(
  '/api/admin/login',
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
app.post('/api/coordinator/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!COORDINATOR_USERNAME || !COORDINATOR_PASSWORD) {
    return res.status(503).json({ error: 'Coordinator account is not configured. Set COORDINATOR_USERNAME and COORDINATOR_PASSWORD in Render Environment.' });
  }
  if (username !== COORDINATOR_USERNAME || password !== COORDINATOR_PASSWORD) {
    return res.status(401).json({ error: 'Invalid coordinator username or password' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { expiresAt: Date.now() + SESSION_TTL_MS, role: 'coordinator' });
  return res.json({ token, role: 'coordinator' });
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

        const db =
          await readDB();

        let items =
          Array.isArray(db[name])
            ? db[name]
            : [];


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

          id:
            nextId(
              db[name]
            ),

          ...body

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
  'donors'
].forEach(
  crudRoutes
);


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

          submissionData.internshipId =
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


        const result =
          await pool.query(

            `INSERT INTO ${table} (data)
             VALUES ($1::jsonb)
             RETURNING id, data, created_at`,

            [
              JSON.stringify(
                submissionData
              )
            ]

          );


        const row =
          result.rows[0];


        res.status(201).json({

          ok: true,

          id:
            row.id

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

        const result =
          await pool.query(

            `SELECT id, data, created_at
             FROM ${table}
             ORDER BY created_at DESC`

          );


        const rows =
          result.rows.map(
            row => ({

              id:
                row.id,

              submittedAt:
                row.created_at,

              ...(row.data || {})

            })
          );


        res.json(rows);


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



/* =========================================================
   STUDENT INTERNSHIP APPROVAL SYSTEM
   ========================================================= */

/*
 * Create the internships table automatically if it does not
 * already exist. The rest of this server stores submission
 * payloads in JSONB, so this follows the same pattern.
 */
const internshipTableReady =
  pool.query(`
    CREATE TABLE IF NOT EXISTS internships (
      id SERIAL PRIMARY KEY,
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `)
  .catch(error => {
    console.error(
      'INTERNSHIP TABLE INIT ERROR:',
      error
    );
    throw error;
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
const projectSubmissionTableReady = pool.query(`
  CREATE TABLE IF NOT EXISTS project_submissions (
    id SERIAL PRIMARY KEY,
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`).catch(error => {
  console.error('PROJECT SUBMISSIONS TABLE INIT ERROR:', error);
  throw error;
});

app.post('/api/projectSubmissions', async (req, res) => {
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
    const result = await pool.query('SELECT id, data, created_at FROM project_submissions ORDER BY created_at DESC');
    return res.json(result.rows.map(row => ({ id: row.id, submittedAt: row.created_at, ...(row.data || {}) })));
  } catch (error) {
    console.error('GET /api/projectSubmissions:', error);
    return res.status(500).json({ error: 'Could not load project submissions.' });
  }
});

app.delete('/api/projectSubmissions/:id', requireAdmin, async (req, res) => {
  try {
    await projectSubmissionTableReady;
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid project submission ID.' });
    const result = await pool.query('DELETE FROM project_submissions WHERE id = $1 RETURNING id', [id]);
    if (!result.rowCount) return res.status(404).json({ error: 'Project submission not found.' });
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
const studentAccountsTableReady = pool.query(`
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
`).catch(error => { console.error('STUDENT ACCOUNTS TABLE INIT ERROR:', error); throw error; });

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

app.post('/api/student/signup', async (req,res)=>{
  try{
    await Promise.all([studentAccountsTableReady,internshipTableReady]);
    const body=req.body||{};
    const username=String(body.username||'').trim();
    const email=String(body.email||'').trim().toLowerCase();
    const password=String(body.password||'');
    const application=body.application&&typeof body.application==='object'?body.application:{};
    if(!/^[a-zA-Z0-9_.-]{4,32}$/.test(username)) return res.status(400).json({error:'Username 4–32 characters का रखें; letters, numbers, dot, underscore या hyphen इस्तेमाल करें।'});
    if(!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({error:'Valid email address भरें।'});
    if(password.length<10) return res.status(400).json({error:'Password कम से कम 10 characters का होना चाहिए।'});
    if(!String(application.studentName||application.name||'').trim()) return res.status(400).json({error:'Student registration form में पूरा नाम भरें।'});
    if(!String(application.mobile||application.phone||'').trim()) return res.status(400).json({error:'Mobile number भरें।'});
    const salt=crypto.randomBytes(16).toString('hex');
    const passwordHash=await hashStudentPassword(password,salt);
    const publicId=makePublicStudentId();
    const appData={...application,studentName:String(application.studentName||application.name).trim(),email,mobile:String(application.mobile||application.phone).trim(),status:'pending',studentAccount:true,publicProfileId:publicId,submittedAt:new Date().toISOString()};
    const created=await pool.query('INSERT INTO internships (data) VALUES ($1::jsonb) RETURNING id, data, created_at',[JSON.stringify(appData)]);
    const internshipId=created.rows[0].id;
    const accountResult=await pool.query('INSERT INTO internship_student_accounts (username,email,password_salt,password_hash,public_id,internship_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, username, email, public_id, internship_id, created_at',[username,email,salt,passwordHash,publicId,internshipId]);
    const account=accountResult.rows[0];
    const token=makeStudentToken();
    studentSessions.set(token,{accountId:account.id,expiresAt:Date.now()+STUDENT_SESSION_TTL_MS});
    return res.status(201).json({ok:true,token,student:{id:account.id,username:account.username,email:account.email,publicId:account.public_id,uniqueUrl:studentPublicUrl(account.public_id),application:{id:internshipId,...(created.rows[0].data||{}),submittedAt:created.rows[0].created_at}}});
  }catch(error){
    if(error.code==='23505') return res.status(409).json({error:'यह Username या Email पहले से registered है। दूसरा इस्तेमाल करें या Login करें।'});
    console.error('STUDENT SIGNUP ERROR:',error);
    return res.status(500).json({error:'Student account नहीं बन सका। कृपया बाद में प्रयास करें।'});
  }
});

app.post('/api/student/login', async (req,res)=>{
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
   START SERVER
   ========================================================= */

Promise.all([internshipTableReady, projectSubmissionTableReady, studentAccountsTableReady])
  .then(() => {

    app.listen(
      PORT,
      () => {

        console.log(
          '======================================'
        );

    console.log(
      'Nisha Seva backend running'
    );

    console.log(
      `Port: ${PORT}`
    );

    console.log(
      'Admin panel: /admin'
    );

        console.log(
          `Volunteer verification: ${PUBLIC_BASE_URL}/verify/volunteer/<code>`
        );

        console.log(
          'Student internship API: /api/internships'
        );

        console.log(
          '======================================'
        );

      }
    );

  })
  .catch(error => {

    console.error(
      'SERVER STARTUP FAILED:',
      error
    );

    process.exit(1);

  });
