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

  const expiry =
    token &&
    sessions.get(token);

  if (
    !expiry ||
    expiry < Date.now()
  ) {

    return res.status(401).json({
      error: 'Unauthorized'
    });

  }

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

      sessions.set(
        token,
        Date.now() +
        SESSION_TTL_MS
      );

      return res.json({
        token
      });

    }

    res.status(401).json({
      error:
        'Invalid username or password'
    });

  }
);


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

      const {
        error
      } =
        await supabase.storage
          .from('gallery')
          .upload(
            uploadedFileName,
            req.file.buffer,
            {
              contentType:
                req.file.mimetype,

              cacheControl:
                '3600',

              upsert:
                false
            }
          );


      if (error) {

        console.error(
          'Supabase upload error:',
          error
        );

        return res.status(500).json({
          error:
            'Image upload failed',
          details:
            error.message
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
   START SERVER
   ========================================================= */

Promise.all([internshipTableReady, projectSubmissionTableReady])
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
