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
  'donors',
  'impactLocations', 'missions', 'impactStories', 'communityEvents', 'knowledgeLibrary'

].forEach(
  crudRoutes
);

// Certificate records are private to admins. Public visitors can only verify one ID.
app.get('/api/certificates', requireAdmin, async (req, res) => {
  try { const db = await readDB(); res.json(Array.isArray(db.certificates) ? db.certificates : []); }
  catch (e) { console.error('GET /api/certificates', e); res.status(500).json({error:'Database error'}); }
});
app.post('/api/certificates', requireAdmin, async (req, res) => {
  try { const db = await readDB(); db.certificates = Array.isArray(db.certificates) ? db.certificates : [];
    const body = req.body || {}; const item = {id: nextId(db.certificates), ...body}; db.certificates.push(item); await writeDB(db); res.status(201).json(item);
  } catch(e) { console.error('POST /api/certificates',e); res.status(500).json({error:'Database error'}); }
});
app.put('/api/certificates/:id', requireAdmin, async (req, res) => {
  try { const db=await readDB(); db.certificates=Array.isArray(db.certificates)?db.certificates:[]; const id=Number(req.params.id); const i=db.certificates.findIndex(x=>Number(x.id)===id); if(i<0)return res.status(404).json({error:'Not found'}); db.certificates[i]={...db.certificates[i],...(req.body||{}),id}; await writeDB(db); res.json(db.certificates[i]);
  } catch(e) { console.error('PUT /api/certificates',e); res.status(500).json({error:'Database error'}); }
});
app.delete('/api/certificates/:id', requireAdmin, async (req, res) => {
  try { const db=await readDB(); db.certificates=Array.isArray(db.certificates)?db.certificates:[]; const id=Number(req.params.id); const before=db.certificates.length; db.certificates=db.certificates.filter(x=>Number(x.id)!==id); if(before===db.certificates.length)return res.status(404).json({error:'Not found'}); await writeDB(db); res.json({ok:true}); }
  catch(e) { console.error('DELETE /api/certificates',e); res.status(500).json({error:'Database error'}); }
});
app.get('/api/certificate-verify/:certificateId', async (req, res) => {
  try {
    const wanted=String(req.params.certificateId||'').trim().toLowerCase();
    if(!wanted || wanted.length>100) return res.status(400).json({valid:false,error:'Invalid certificate ID'});
    const db=await readDB(); const list=Array.isArray(db.certificates)?db.certificates:[];
    const item=list.find(x=>String(x.certificateId||x.certificate_id||'').trim().toLowerCase()===wanted);
    if(!item || String(item.status||'active').toLowerCase()==='revoked') return res.json({valid:false,message:'Certificate not found or revoked'});
    res.json({valid:true,certificate:{certificateId:item.certificateId||item.certificate_id,name:item.name||item.studentName||'',course:item.course||item.program||'',issueDate:item.issueDate||item.issuedAt||'',issuer:'Nisha Seva Foundation',status:'Valid'}});
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

const donationsTableReady = pool.query(`CREATE TABLE IF NOT EXISTS donations (
 id BIGSERIAL PRIMARY KEY, order_id VARCHAR(80) UNIQUE NOT NULL, receipt_no VARCHAR(80) UNIQUE NOT NULL,
 donor_name VARCHAR(120) NOT NULL, donor_phone VARCHAR(20) NOT NULL, donor_email VARCHAR(180), amount NUMERIC(12,2) NOT NULL,
 currency VARCHAR(3) NOT NULL DEFAULT 'INR', payment_status VARCHAR(20) NOT NULL DEFAULT 'PENDING', cf_payment_id VARCHAR(100),
 payment_time TIMESTAMPTZ, sms_status VARCHAR(30) NOT NULL DEFAULT 'NOT_SENT', sms_error TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`).catch(e=>{console.error('DONATIONS TABLE INIT ERROR:',e);throw e;});

async function cashfreeRequest(url, options={}) {
  if (!CASHFREE_APP_ID || !CASHFREE_SECRET_KEY) throw new Error('Cashfree API credentials are not configured in Render Environment.');
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
  const payment=paymentInfo.payment || paymentInfo;
  const paymentId=payment.cf_payment_id || paymentInfo.cf_payment_id || null;
  const result=await pool.query("UPDATE donations SET payment_status='PAID',cf_payment_id=COALESCE($2,cf_payment_id),payment_time=COALESCE($3::timestamptz,NOW()),updated_at=NOW() WHERE order_id=$1 RETURNING *",[orderId,paymentId,payment.payment_time||paymentInfo.payment_time||null]);
  const row=result.rows[0];
  await sendDonationSms(row);
  const refreshed=await pool.query('SELECT * FROM donations WHERE order_id=$1',[orderId]);
  return refreshed.rows[0];
}

app.post('/api/donations/create-order', async(req,res)=>{
 try{
  await donationsTableReady;
  const name=String(req.body.name||'').trim().slice(0,120), phone=String(req.body.phone||'').replace(/\D/g,''), email=String(req.body.email||'').trim().slice(0,180), amount=Number(req.body.amount);
  if(name.length<2) return res.status(400).json({error:'Please enter donor name.'});
  if(!/^[6-9]\d{9}$/.test(phone)) return res.status(400).json({error:'Enter a valid 10-digit Indian mobile number.'});
  if(!Number.isFinite(amount)||amount<1||amount>1000000||Math.round(amount*100)!==amount*100) return res.status(400).json({error:'Enter a valid donation amount.'});
  if(email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:'Enter a valid email address or leave it blank.'});
  const orderId='NSFDON_'+Date.now()+'_'+crypto.randomBytes(4).toString('hex');
  const receiptNo='NSF-'+new Date().getFullYear()+'-'+crypto.randomBytes(4).toString('hex').toUpperCase();
  const customerId='donor_'+crypto.randomBytes(8).toString('hex');
  await pool.query('INSERT INTO donations(order_id,receipt_no,donor_name,donor_phone,donor_email,amount) VALUES($1,$2,$3,$4,$5,$6)',[orderId,receiptNo,name,phone,email||null,amount]);
  const created=await cashfreeRequest(`${CASHFREE_BASE}/orders`,{method:'POST',body:JSON.stringify({order_id:orderId,order_amount:amount,order_currency:'INR',customer_details:{customer_id:customerId,customer_name:name,customer_email:email||undefined,customer_phone:phone},order_meta:{return_url:`${DONATION_SITE_URL}/?order_id={order_id}#donate`,notify_url:`${PUBLIC_BASE_URL}/api/donations/webhook`},order_note:'Donation to Nisha Seva Foundation'})});
  res.json({ok:true,orderId,paymentSessionId:created.payment_session_id,mode:CASHFREE_MODE});
 }catch(e){console.error('CREATE DONATION ORDER ERROR:',e);res.status(500).json({error:e.message||'Could not create Cashfree order.'});}
});

app.get('/api/donations/status/:orderId',async(req,res)=>{
 try{
  await donationsTableReady;
  const orderId=String(req.params.orderId||'').slice(0,80);
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
const communityRequestsTableReady = pool.query(`
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
`);

app.post('/api/community-requests', async (req, res) => {
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
   START SERVER
   ========================================================= */

Promise.all([internshipTableReady, projectSubmissionTableReady, studentAccountsTableReady, donationsTableReady])
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
