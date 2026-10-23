require('dotenv').config();

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const nodemailer = require('nodemailer');

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

// Set both values in Hostinger Environment for a separate coordinator account.
const COORDINATOR_USERNAME = process.env.COORDINATOR_USERNAME || '';
const COORDINATOR_PASSWORD = process.env.COORDINATOR_PASSWORD || '';

const PUBLIC_BASE_URL =
  process.env.PUBLIC_BASE_URL ||
  'https://api.nishasevafoundation.org';


/* =========================================================
   MIDDLEWARE
   ========================================================= */

const allowedOrigins = String(process.env.ALLOWED_ORIGINS || 'https://nishasevafoundation.org')
  .split(',').map(value => value.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed by CORS'));
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));

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
  if (session.role === 'coordinator' && !(/^\/api\/internships(?:\/|$)/.test(req.path) || req.path === '/api/admin/logout' || req.path === '/api/student/accounts' || /^\/api\/projectSubmissions(?:\/|$)/.test(req.path) || /^\/api\/tasks(?:\/|$)/.test(req.path) || /^\/api\/impact-passport(?:\/|$)/.test(req.path))) {
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


        const row = result.rows[0];
        let referenceNo = null;
        if (name === 'internships') {
          referenceNo = `NSF-INT-${row.id}`;
          const updatedData = { ...(row.data || {}), referenceNo, applicationReference: referenceNo };
          await pool.query('UPDATE internships SET data=$1::jsonb WHERE id=$2', [JSON.stringify(updatedData), row.id]);
        }

        res.status(201).json({
          ok: true,
          id: row.id,
          referenceNo
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



/* ADDITIVE: Coordinator Task Management + Student Impact Passport */
const nsfTasksReady = pool.query("CREATE TABLE IF NOT EXISTS nsf_tasks (id BIGSERIAL PRIMARY KEY,title TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',assigned_student_account_id BIGINT,assigned_team TEXT NOT NULL DEFAULT '',priority TEXT NOT NULL DEFAULT 'normal' CHECK(priority IN ('low','normal','high','urgent')),status TEXT NOT NULL DEFAULT 'todo' CHECK(status IN ('todo','in_progress','blocked','review','done','cancelled')),due_date DATE,created_by_role TEXT NOT NULL DEFAULT 'admin' CHECK(created_by_role IN ('admin','coordinator')),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())").catch(e=>{console.error('NSF TASK TABLE INIT:',e);throw e;});
const nsfPassportReady = pool.query("CREATE TABLE IF NOT EXISTS nsf_impact_passport_entries (id BIGSERIAL PRIMARY KEY,student_account_id BIGINT NOT NULL,entry_type TEXT NOT NULL DEFAULT 'achievement' CHECK(entry_type IN ('achievement','skill','service_hours','project','certificate')),title TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',evidence_url TEXT,metric_value NUMERIC(10,2),metric_unit TEXT,verification_status TEXT NOT NULL DEFAULT 'pending' CHECK(verification_status IN ('pending','verified','rejected')),reviewed_by_role TEXT,reviewed_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())").catch(e=>{console.error('NSF PASSPORT TABLE INIT:',e);throw e;});
const nsfId = v => Number.isSafeInteger(Number(v)) && Number(v)>0 ? Number(v) : null;
const nsfText = (v,n=3000) => String(v==null?'':v).trim().slice(0,n);
const nsfActorRole = req => req.userRole==='coordinator'?'coordinator':'admin';

app.get('/api/tasks',requireAdmin,async(req,res)=>{try{await nsfTasksReady;const r=await pool.query("SELECT id,title,description,assigned_student_account_id,assigned_team,priority,status,due_date,created_by_role,created_at,updated_at FROM nsf_tasks ORDER BY CASE priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 ELSE 4 END,due_date ASC NULLS LAST,created_at DESC LIMIT 500");res.set('Cache-Control','no-store');res.json({tasks:r.rows});}catch(e){console.error('TASK LIST',e);res.status(500).json({error:'Task list load नहीं हो सकी।'});}});
app.post('/api/tasks',requireAdmin,async(req,res)=>{try{await nsfTasksReady;const b=req.body||{},title=nsfText(b.title,180),desc=nsfText(b.description),sid=b.assignedStudentAccountId?nsfId(b.assignedStudentAccountId):null,team=nsfText(b.assignedTeam,120),priority=['low','normal','high','urgent'].includes(b.priority)?b.priority:'normal',due=b.dueDate?String(b.dueDate).slice(0,10):null;if(!title)return res.status(400).json({error:'Task title जरूरी है।'});if(b.assignedStudentAccountId&&!sid)return res.status(400).json({error:'Student ID गलत है।'});if(due&&!/^\d{4}-\d{2}-\d{2}$/.test(due))return res.status(400).json({error:'Due date गलत है।'});if(sid){await studentAccountsTableReady;const st=await pool.query('SELECT id FROM internship_student_accounts WHERE id=$1',[sid]);if(!st.rows.length)return res.status(404).json({error:'Student account नहीं मिला।'});}const r=await pool.query("INSERT INTO nsf_tasks(title,description,assigned_student_account_id,assigned_team,priority,due_date,created_by_role) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,title,description,assigned_student_account_id,assigned_team,priority,status,due_date,created_by_role,created_at,updated_at",[title,desc,sid,team,priority,due,nsfActorRole(req)]);res.status(201).json({ok:true,task:r.rows[0]});}catch(e){console.error('TASK CREATE',e);res.status(500).json({error:'Task create नहीं हो सका।'});}});
app.patch('/api/tasks/:id/status',requireAdmin,async(req,res)=>{try{await nsfTasksReady;const id=nsfId(req.params.id),status=String((req.body||{}).status||'');if(!id)return res.status(400).json({error:'Task ID गलत है।'});if(!['todo','in_progress','blocked','review','done','cancelled'].includes(status))return res.status(400).json({error:'Task status मान्य नहीं है।'});const r=await pool.query('UPDATE nsf_tasks SET status=$1,updated_at=NOW() WHERE id=$2 RETURNING id,title,description,assigned_student_account_id,assigned_team,priority,status,due_date,created_by_role,created_at,updated_at',[status,id]);if(!r.rows.length)return res.status(404).json({error:'Task नहीं मिला।'});res.json({ok:true,task:r.rows[0]});}catch(e){console.error('TASK UPDATE',e);res.status(500).json({error:'Task update नहीं हो सका।'});}});
app.get('/api/student/tasks',studentAuth,async(req,res)=>{try{await nsfTasksReady;const r=await pool.query("SELECT id,title,description,assigned_team,priority,status,due_date,created_at,updated_at FROM nsf_tasks WHERE assigned_student_account_id=$1 ORDER BY due_date ASC NULLS LAST,created_at DESC LIMIT 200",[req.studentAccountId]);res.set('Cache-Control','no-store');res.json({tasks:r.rows});}catch(e){console.error('STUDENT TASK LIST',e);res.status(500).json({error:'Assigned tasks load नहीं हो सके।'});}});
app.patch('/api/student/tasks/:id/status',studentAuth,async(req,res)=>{try{await nsfTasksReady;const id=nsfId(req.params.id),status=String((req.body||{}).status||'');if(!id)return res.status(400).json({error:'Task ID गलत है।'});if(!['in_progress','blocked','review'].includes(status))return res.status(400).json({error:'Student केवल In progress, Blocked या Review status चुन सकता है।'});const r=await pool.query("UPDATE nsf_tasks SET status=$1,updated_at=NOW() WHERE id=$2 AND assigned_student_account_id=$3 RETURNING id,title,status,updated_at",[status,id,req.studentAccountId]);if(!r.rows.length)return res.status(404).json({error:'Assigned task नहीं मिला।'});res.json({ok:true,task:r.rows[0]});}catch(e){console.error('STUDENT TASK UPDATE',e);res.status(500).json({error:'Task status update नहीं हो सका।'});}});
app.get('/api/impact-passport/me',studentAuth,async(req,res)=>{try{await nsfPassportReady;const r=await pool.query('SELECT id,entry_type,title,description,evidence_url,metric_value,metric_unit,verification_status,reviewed_at,created_at FROM nsf_impact_passport_entries WHERE student_account_id=$1 ORDER BY created_at DESC LIMIT 300',[req.studentAccountId]);res.set('Cache-Control','no-store');res.json({entries:r.rows});}catch(e){console.error('PASSPORT ME',e);res.status(500).json({error:'Impact Passport load नहीं हो सका।'});}});
app.get('/api/impact-passport/:studentAccountId',requireAdmin,async(req,res)=>{try{await nsfPassportReady;const sid=nsfId(req.params.studentAccountId);if(!sid)return res.status(400).json({error:'Student ID गलत है।'});const st=await pool.query('SELECT id,username,email,public_id FROM internship_student_accounts WHERE id=$1',[sid]);if(!st.rows.length)return res.status(404).json({error:'Student account नहीं मिला।'});const r=await pool.query('SELECT id,entry_type,title,description,evidence_url,metric_value,metric_unit,verification_status,reviewed_by_role,reviewed_at,created_at FROM nsf_impact_passport_entries WHERE student_account_id=$1 ORDER BY created_at DESC LIMIT 300',[sid]);res.set('Cache-Control','no-store');res.json({student:st.rows[0],entries:r.rows});}catch(e){console.error('PASSPORT ADMIN',e);res.status(500).json({error:'Impact Passport load नहीं हो सका।'});}});
app.post('/api/impact-passport/:studentAccountId/entries',requireAdmin,async(req,res)=>{try{await nsfPassportReady;const sid=nsfId(req.params.studentAccountId),b=req.body||{},title=nsfText(b.title,180),desc=nsfText(b.description),type=['achievement','skill','service_hours','project','certificate'].includes(b.entryType)?b.entryType:'achievement',url=nsfText(b.evidenceUrl,1000)||null,unit=nsfText(b.metricUnit,40)||null,value=b.metricValue==null||b.metricValue===''?null:Number(b.metricValue);if(!sid||!title)return res.status(400).json({error:'Student ID और title जरूरी हैं।'});if(value!==null&&(!Number.isFinite(value)||value<0||value>10000000))return res.status(400).json({error:'Metric value गलत है।'});const st=await pool.query('SELECT id FROM internship_student_accounts WHERE id=$1',[sid]);if(!st.rows.length)return res.status(404).json({error:'Student account नहीं मिला।'});const r=await pool.query("INSERT INTO nsf_impact_passport_entries(student_account_id,entry_type,title,description,evidence_url,metric_value,metric_unit) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,student_account_id,entry_type,title,description,evidence_url,metric_value,metric_unit,verification_status,created_at",[sid,type,title,desc,url,value,unit]);res.status(201).json({ok:true,entry:r.rows[0]});}catch(e){console.error('PASSPORT CREATE',e);res.status(500).json({error:'Passport entry save नहीं हो सकी।'});}});
app.patch('/api/impact-passport/entries/:entryId/review',requireAdmin,async(req,res)=>{try{await nsfPassportReady;const id=nsfId(req.params.entryId),status=String((req.body||{}).verificationStatus||'');if(!id)return res.status(400).json({error:'Entry ID गलत है।'});if(!['pending','verified','rejected'].includes(status))return res.status(400).json({error:'Verification status गलत है।'});const r=await pool.query('UPDATE nsf_impact_passport_entries SET verification_status=$1,reviewed_by_role=$2,reviewed_at=NOW(),updated_at=NOW() WHERE id=$3 RETURNING id,student_account_id,entry_type,title,description,evidence_url,metric_value,metric_unit,verification_status,reviewed_by_role,reviewed_at,created_at',[status,nsfActorRole(req),id]);if(!r.rows.length)return res.status(404).json({error:'Passport entry नहीं मिली।'});res.json({ok:true,entry:r.rows[0]});}catch(e){console.error('PASSPORT REVIEW',e);res.status(500).json({error:'Passport review नहीं हो सकी।'});}});


/* =========================================================
   NSF IMPACT PLATFORM: SAFE ADDITIVE API FOUNDATION
   Remaining features use explicit public/verified views and authenticated writes.
   ========================================================= */
const nsfExpansionReady = pool.query("SELECT to_regclass('public.nsf_villages') AS villages")
  .then(r=>{if(!r.rows[0]||!r.rows[0].villages) throw new Error('Apply migrations/20261024_impact_platform_expansion.sql after backup/staging validation'); return true;});

app.get('/api/public/impact-map',async(req,res)=>{try{await nsfExpansionReady;const r=await pool.query("SELECT v.id,v.name,v.district,v.public_description,v.latitude,v.longitude,COUNT(p.id)::int AS project_count,COUNT(p.id) FILTER (WHERE p.status='completed')::int AS completed_projects FROM nsf_villages v LEFT JOIN nsf_village_projects p ON p.village_id=v.id AND p.verified=TRUE WHERE v.visibility='public' GROUP BY v.id ORDER BY v.name LIMIT 500");res.set('Cache-Control','public, max-age=60');res.json({villages:r.rows});}catch(e){console.error('PUBLIC IMPACT MAP',e);res.status(503).json({error:'Impact map अभी configure नहीं है।'});}});
app.get('/api/public/impact-report',async(req,res)=>{try{await nsfExpansionReady;const r=await pool.query("SELECT kind,COUNT(*)::int AS records,SUM(amount_paise)::bigint AS total_amount_paise FROM nsf_impact_transactions WHERE approved=TRUE GROUP BY kind ORDER BY kind");res.set('Cache-Control','public, max-age=60');res.json({summary:r.rows,disclaimer:'केवल स्वीकृत रिकॉर्ड; यह स्वतः ऑडिटेड वित्तीय विवरण नहीं है।'});}catch(e){console.error('IMPACT REPORT',e);res.status(503).json({error:'Impact report अभी configure नहीं है।'});}});
app.get('/api/opportunities',async(req,res)=>{try{await nsfExpansionReady;const r=await pool.query("SELECT o.id,o.title,o.description,o.skills,o.slots,o.start_date,o.end_date,v.name AS village_name FROM nsf_seva_opportunities o LEFT JOIN nsf_villages v ON v.id=o.village_id WHERE o.status='open' AND (o.end_date IS NULL OR o.end_date>=CURRENT_DATE) ORDER BY o.start_date NULLS LAST,o.created_at DESC LIMIT 300");res.set('Cache-Control','no-store');res.json({opportunities:r.rows});}catch(e){console.error('OPPORTUNITIES',e);res.status(503).json({error:'Seva opportunities अभी configure नहीं हैं।'});}});
app.post('/api/opportunities/:id/apply',studentAuth,async(req,res)=>{try{await nsfExpansionReady;const id=nsfId(req.params.id);if(!id)return res.status(400).json({error:'Opportunity ID गलत है।'});const exists=await pool.query("SELECT id FROM nsf_seva_opportunities WHERE id=$1 AND status='open' AND (end_date IS NULL OR end_date>=CURRENT_DATE)",[id]);if(!exists.rows.length)return res.status(404).json({error:'Opportunity उपलब्ध नहीं है।'});const note=nsfText((req.body||{}).note,1000);const r=await pool.query("INSERT INTO nsf_opportunity_applications(opportunity_id,student_account_id,note) VALUES($1,$2,$3) ON CONFLICT(opportunity_id,student_account_id) DO NOTHING RETURNING id,status",[id,req.studentAccountId,note]);res.status(r.rows.length?201:200).json({ok:true,application:r.rows[0]||{status:'already_applied'}});}catch(e){console.error('OPPORTUNITY APPLY',e);res.status(500).json({error:'Application save नहीं हो सकी।'});}});
app.get('/api/challenges',async(req,res)=>{try{await nsfExpansionReady;const r=await pool.query("SELECT id,title,description,start_date,end_date,status FROM nsf_90day_challenges WHERE status='active' ORDER BY start_date DESC LIMIT 100");res.json({challenges:r.rows});}catch(e){console.error('CHALLENGES',e);res.status(503).json({error:'Challenges अभी configure नहीं हैं।'});}});
app.post('/api/challenges/:id/checkins',studentAuth,async(req,res)=>{try{await nsfExpansionReady;const id=nsfId(req.params.id),b=req.body||{},goal=nsfText(b.goal,500),note=nsfText(b.progressNote,2000),value=b.progressValue==null||b.progressValue===''?null:Number(b.progressValue);if(!id)return res.status(400).json({error:'Challenge ID गलत है।'});if(value!==null&&(!Number.isFinite(value)||value<0||value>1000000))return res.status(400).json({error:'Progress value गलत है।'});let enrollment=await pool.query("SELECT e.id FROM nsf_challenge_enrollments e JOIN nsf_90day_challenges c ON c.id=e.challenge_id WHERE e.challenge_id=$1 AND e.student_account_id=$2 AND c.status='active'",[id,req.studentAccountId]);if(!enrollment.rows.length){const challenge=await pool.query("SELECT id FROM nsf_90day_challenges WHERE id=$1 AND status='active' AND start_date<=CURRENT_DATE AND end_date>=CURRENT_DATE",[id]);if(!challenge.rows.length)return res.status(404).json({error:'Active challenge नहीं मिला।'});const created=await pool.query("INSERT INTO nsf_challenge_enrollments(challenge_id,student_account_id,goal) VALUES($1,$2,$3) ON CONFLICT(challenge_id,student_account_id) DO UPDATE SET goal=CASE WHEN EXCLUDED.goal='' THEN nsf_challenge_enrollments.goal ELSE EXCLUDED.goal END RETURNING id",[id,req.studentAccountId,goal]);enrollment=created;}const r=await pool.query("INSERT INTO nsf_challenge_checkins(enrollment_id,progress_note,progress_value,evidence_url) VALUES($1,$2,$3,$4) ON CONFLICT(enrollment_id,checkin_date) DO UPDATE SET progress_note=EXCLUDED.progress_note,progress_value=EXCLUDED.progress_value,evidence_url=EXCLUDED.evidence_url RETURNING id,checkin_date,progress_note,progress_value,reviewed",[enrollment.rows[0].id,note,value,nsfText(b.evidenceUrl,1000)||null]);res.status(201).json({ok:true,checkin:r.rows[0]});}catch(e){console.error('CHALLENGE CHECKIN',e);res.status(500).json({error:'Challenge check-in save नहीं हो सका।'});}});
app.post('/api/issues',async(req,res)=>{try{await nsfExpansionReady;const b=req.body||{},title=nsfText(b.title,180),description=nsfText(b.description,3000),category=nsfText(b.category,80)||'general',villageId=b.villageId?nsfId(b.villageId):null;if(!title||!description)return res.status(400).json({error:'Issue title और विवरण जरूरी हैं।'});const ref=crypto.randomBytes(6).toString('hex').toUpperCase();if(villageId){const v=await pool.query("SELECT id FROM nsf_villages WHERE id=$1 AND visibility='public'",[villageId]);if(!v.rows.length)return res.status(400).json({error:'Village ID मान्य नहीं है।'});}const r=await pool.query("INSERT INTO nsf_community_issues(village_id,title,description,category,public_reference,reporter_name,reporter_contact) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,public_reference,status,created_at",[villageId,title,description,category,ref,nsfText(b.reporterName,120)||null,nsfText(b.reporterContact,160)||null]);await pool.query("INSERT INTO nsf_issue_timeline(issue_id,status,public_note,created_by_role) VALUES($1,'submitted','समस्या प्राप्त हुई।','system')",[r.rows[0].id]);res.status(201).json({ok:true,issue:r.rows[0],message:'इस reference से प्रगति देखें।'});}catch(e){console.error('ISSUE CREATE',e);res.status(503).json({error:'Issue submission अभी configure नहीं है।'});}});
app.get('/api/issues/:reference/timeline',async(req,res)=>{try{await nsfExpansionReady;const ref=nsfText(req.params.reference,30).toUpperCase();const issue=await pool.query("SELECT id,public_reference,title,category,status,created_at,updated_at FROM nsf_community_issues WHERE public_reference=$1 AND public_visible=TRUE",[ref]);if(!issue.rows.length)return res.status(404).json({error:'Public issue reference नहीं मिला।'});const timeline=await pool.query("SELECT status,public_note,created_at FROM nsf_issue_timeline WHERE issue_id=$1 ORDER BY created_at ASC",[issue.rows[0].id]);res.set('Cache-Control','no-store');res.json({issue:issue.rows[0],timeline:timeline.rows});}catch(e){console.error('ISSUE TIMELINE',e);res.status(503).json({error:'Issue timeline अभी configure नहीं है।'});}});
app.get('/api/public/villages/:id/scorecard',async(req,res)=>{try{await nsfExpansionReady;const id=nsfId(req.params.id);if(!id)return res.status(400).json({error:'Village ID गलत है।'});const v=await pool.query("SELECT id,name,district,public_description FROM nsf_villages WHERE id=$1 AND visibility='public'",[id]);if(!v.rows.length)return res.status(404).json({error:'Village नहीं मिला।'});const indicators=await pool.query("SELECT indicator_key,label,value,unit,public_note,measured_on FROM nsf_development_indicators WHERE village_id=$1 AND verified=TRUE ORDER BY measured_on DESC LIMIT 300",[id]);const projects=await pool.query("SELECT id,title,description,status,public_summary FROM nsf_village_projects WHERE village_id=$1 AND verified=TRUE ORDER BY created_at DESC LIMIT 100",[id]);res.json({village:v.rows[0],indicators:indicators.rows,projects:projects.rows,scoringNote:'यह scorecard केवल सत्यापित indicators दिखाता है; कोई composite score तब तक नहीं निकाला जाता जब तक approved scoring methodology निर्धारित न हो।'});}catch(e){console.error('VILLAGE SCORECARD',e);res.status(503).json({error:'Scorecard अभी configure नहीं है।'});}});
app.get('/api/impact-profile/me',studentAuth,async(req,res)=>{try{await nsfExpansionReady;const r=await pool.query("SELECT p.student_account_id,p.strengths,p.interests,p.verified_hours,p.completed_projects,p.last_calculated_at FROM nsf_impact_dna_profiles p WHERE p.student_account_id=$1",[req.studentAccountId]);res.set('Cache-Control','no-store');res.json({profile:r.rows[0]||{student_account_id:req.studentAccountId,strengths:[],interests:[],verified_hours:0,completed_projects:0,notCalculated:true}});}catch(e){console.error('IMPACT DNA',e);res.status(503).json({error:'Impact DNA अभी configure नहीं है।'});}});
app.post('/api/ai/research/draft',requireAdmin,async(req,res)=>{try{await nsfExpansionReady;const b=req.body||{},topic=nsfText(b.topic,240),notes=nsfText(b.notes,6000),villageId=b.villageId?nsfId(b.villageId):null;if(!topic)return res.status(400).json({error:'Research topic जरूरी है।'});const draft=['फील्ड रिसर्च ड्राफ्ट — मानव समीक्षा आवश्यक','विषय: '+topic,'','दिए गए नोट्स:',notes||'(अभी कोई फील्ड नोट नहीं दिया गया।)','','सुझाए गए अगले कदम:','1. स्रोत और तारीख की पुष्टि करें।','2. सर्वेक्षण के नमूने और सीमाएँ दर्ज करें।','3. निजी पहचान योग्य जानकारी हटाएँ।','4. निष्कर्षों को प्रकाशित करने से पहले coordinator द्वारा सत्यापित करें।'].join('\n');const r=await pool.query("INSERT INTO nsf_ai_research_sessions(created_by_role,village_id,topic,language,input_notes,draft_output,reviewed) VALUES($1,$2,$3,$4,$5,$6,FALSE) RETURNING id,topic,language,draft_output,reviewed,created_at",[nsfActorRole(req),villageId,topic,nsfText(b.language,10)||'hi',notes,draft]);res.status(201).json({session:r.rows[0],notice:'यह संरचित प्रारंभिक ड्राफ्ट है, AI-generated verified finding नहीं। इसे प्रकाशित करने से पहले review करें।'});}catch(e){console.error('RESEARCH DRAFT',e);res.status(503).json({error:'Research draft अभी configure नहीं है।'});}});
app.post('/api/voice/transcript',studentAuth,async(req,res)=>{try{await nsfExpansionReady;const b=req.body||{},transcript=nsfText(b.transcript,5000),purpose=nsfText(b.purpose,80)||'general';if(!transcript)return res.status(400).json({error:'Voice transcript खाली है। पहले transcription को review करें।'});const r=await pool.query("INSERT INTO nsf_voice_submissions(student_account_id,purpose,transcript) VALUES($1,$2,$3) RETURNING id,purpose,transcript,reviewed,created_at",[req.studentAccountId,purpose,transcript]);res.status(201).json({ok:true,submission:r.rows[0],notice:'यह endpoint reviewed transcript save करता है; speech-to-text service अलग से configure करनी होगी।'});}catch(e){console.error('VOICE SUBMIT',e);res.status(503).json({error:'Voice submission अभी configure नहीं है।'});}});
app.post('/api/admin/villages',requireAdmin,async(req,res)=>{try{await nsfExpansionReady;const b=req.body||{},name=nsfText(b.name,160),district=nsfText(b.district,120)||'Jaipur',desc=nsfText(b.publicDescription,1000),lat=b.latitude==null||b.latitude===''?null:Number(b.latitude),lon=b.longitude==null||b.longitude===''?null:Number(b.longitude);if(!name)return res.status(400).json({error:'Village name जरूरी है।'});if((lat!==null&&(!Number.isFinite(lat)||Math.abs(lat)>90))||(lon!==null&&(!Number.isFinite(lon)||Math.abs(lon)>180)))return res.status(400).json({error:'Coordinates मान्य नहीं हैं।'});const r=await pool.query("INSERT INTO nsf_villages(name,district,public_description,latitude,longitude,visibility) VALUES($1,$2,$3,$4,$5,$6) RETURNING *",[name,district,desc,lat,lon,b.visibility==='private'?'private':'public']);res.status(201).json({ok:true,village:r.rows[0]});}catch(e){console.error('VILLAGE CREATE',e);res.status(503).json({error:'Village create नहीं हो सका।'});}});
app.post('/api/admin/opportunities',requireAdmin,async(req,res)=>{try{await nsfExpansionReady;const b=req.body||{},title=nsfText(b.title,180),desc=nsfText(b.description,3000),slots=Number(b.slots||1);if(!title||!Number.isInteger(slots)||slots<1||slots>10000)return res.status(400).json({error:'Title और valid slots जरूरी हैं।'});const skills=Array.isArray(b.skills)?b.skills.slice(0,30).map(x=>nsfText(x,60)).filter(Boolean):[];const vid=b.villageId?nsfId(b.villageId):null;const r=await pool.query("INSERT INTO nsf_seva_opportunities(title,description,village_id,skills,slots,status,start_date,end_date) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",[title,desc,vid,skills,slots,b.status==='open'?'open':'draft',b.startDate||null,b.endDate||null]);res.status(201).json({ok:true,opportunity:r.rows[0]});}catch(e){console.error('OPPORTUNITY CREATE',e);res.status(503).json({error:'Opportunity create नहीं हो सकी।'});}});
app.post('/api/admin/challenges',requireAdmin,async(req,res)=>{try{await nsfExpansionReady;const b=req.body||{},title=nsfText(b.title,180),start=String(b.startDate||''),end=String(b.endDate||'');if(!title||!/^\d{4}-\d{2}-\d{2}$/.test(start)||!/^\d{4}-\d{2}-\d{2}$/.test(end)||end<start)return res.status(400).json({error:'Title और सही start/end date जरूरी हैं।'});const r=await pool.query("INSERT INTO nsf_90day_challenges(title,description,start_date,end_date,status) VALUES($1,$2,$3,$4,$5) RETURNING *",[title,nsfText(b.description,2000),start,end,b.status==='active'?'active':'draft']);res.status(201).json({ok:true,challenge:r.rows[0]});}catch(e){console.error('CHALLENGE CREATE',e);res.status(503).json({error:'Challenge create नहीं हो सका।'});}});
app.post('/api/admin/issues/:id/timeline',requireAdmin,async(req,res)=>{try{await nsfExpansionReady;const id=nsfId(req.params.id),b=req.body||{},status=String(b.status||''),note=nsfText(b.publicNote,1500);if(!id||!['submitted','reviewing','in_progress','resolved','rejected'].includes(status))return res.status(400).json({error:'Issue ID/status मान्य नहीं है।'});const updated=await pool.query("UPDATE nsf_community_issues SET status=$1,updated_at=NOW() WHERE id=$2 RETURNING id,public_reference,status",[status,id]);if(!updated.rows.length)return res.status(404).json({error:'Issue नहीं मिला।'});await pool.query("INSERT INTO nsf_issue_timeline(issue_id,status,public_note,created_by_role) VALUES($1,$2,$3,$4)",[id,status,note,nsfActorRole(req)]);res.json({ok:true,issue:updated.rows[0]});}catch(e){console.error('ISSUE TIMELINE UPDATE',e);res.status(503).json({error:'Timeline update नहीं हो सकी।'});}});

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

const passwordResetTableReady = pool.query(`
  CREATE TABLE IF NOT EXISTS internship_password_resets (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`).catch(error => { console.error('PASSWORD RESET TABLE INIT ERROR:', error); throw error; });
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
app.post('/api/student/forgot-password', async (req,res) => {
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
app.post('/api/student/reset-password', async (req,res) => {
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

app.post('/api/student/signup', async (req,res)=>{
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
