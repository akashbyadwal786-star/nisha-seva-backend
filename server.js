require('dotenv').config();

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { readDB, writeDB, nextId, pool } = require('./db');
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const app = express();

const PORT = process.env.PORT || 4000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-this-password';

const PUBLIC_BASE_URL =
  process.env.PUBLIC_BASE_URL ||
  'https://nisha-seva-backend.onrender.com';

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

/* ---------- Uploads ---------- */

const uploadsDir = path.join(__dirname, 'uploads');

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

app.use('/uploads', express.static(uploadsDir));
app.use('/admin', express.static(path.join(__dirname, 'admin')));


/* ---------- Admin Auth ---------- */

const sessions = new Map();
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

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

    const token =
      crypto.randomBytes(24).toString('hex');

    sessions.set(
      token,
      Date.now() + SESSION_TTL_MS
    );

    return res.json({
      token
    });
  }

  res.status(401).json({
    error: 'Invalid username or password'
  });
});


/* ---------- Admin Logout ---------- */

app.post('/api/admin/logout', requireAdmin, (req, res) => {

  const token =
    req.headers.authorization.slice(7);

  sessions.delete(token);

  res.json({
    ok: true
  });

});


/* ---------- File Upload ---------- */

const upload = multer({
  storage: multer.memoryStorage(),

  limits: {
    fileSize: 5 * 1024 * 1024
  },

  fileFilter: (req, file, cb) => {

    if (
      file.mimetype &&
      file.mimetype.startsWith('image/')
    ) {

      cb(null, true);

    } else {

      cb(
        new Error(
          'Only image files are allowed'
        )
      );

    }

  }

});


app.post(
  '/api/upload',
  requireAdmin,
  upload.single('file'),
  async (req, res) => {

    try {

      if (!req.file) {

        return res.status(400).json({
          error: 'No file uploaded'
        });

      }

      const ext =
        (
          req.file.originalname
            .split('.')
            .pop() || 'jpg'
        )
        .toLowerCase()
        .replace(/[^a-z0-9]/g, '');

      const fileName =
        `gallery/${Date.now()}-${crypto.randomUUID()}.${ext}`;

      const { error } =
        await supabase.storage
          .from('gallery')
          .upload(
            fileName,
            req.file.buffer,
            {
              contentType: req.file.mimetype,
              upsert: false
            }
          );

      if (error) {

        console.error(
          'Supabase upload error:',
          error
        );

        return res.status(500).json({
          error: 'Image upload failed'
        });

      }

      const { data } =
        supabase.storage
          .from('gallery')
          .getPublicUrl(fileName);

      res.json({
        ok: true,
        url: data.publicUrl
      });

    } catch (error) {

      console.error(
        'POST /api/upload',
        error
      );

      res.status(500).json({
        error: 'Upload failed'
      });

    }

  }
);


/* ---------- Generic CRUD Routes ---------- */

function crudRoutes(name) {

  /* Public read */

  app.get(
    `/api/${name}`,
    async (req, res) => {

      try {

        const db = await readDB();

        res.json(
          db[name] || []
        );

      } catch (error) {

        console.error(
          `GET /api/${name}`,
          error
        );

        res.status(500).json({
          error: 'Database error'
        });

      }

    }
  );


  /* Admin create */

  app.post(
    `/api/${name}`,
    requireAdmin,
    async (req, res) => {

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

        console.error(
          `POST /api/${name}`,
          error
        );

        res.status(500).json({
          error: 'Database error'
        });

      }

    }
  );


  /* Admin update */

  app.put(
    `/api/${name}/:id`,
    requireAdmin,
    async (req, res) => {

      try {

        const db = await readDB();

        const id =
          Number(req.params.id);

        if (!Array.isArray(db[name])) {
          db[name] = [];
        }

        const idx =
          db[name].findIndex(
            item =>
              Number(item.id) === id
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

        res.json(
          db[name][idx]
        );

      } catch (error) {

        console.error(
          `PUT /api/${name}`,
          error
        );

        res.status(500).json({
          error: 'Database error'
        });

      }

    }
  );


  /* Admin delete */

  app.delete(
    `/api/${name}/:id`,
    requireAdmin,
    async (req, res) => {

      try {

        const db = await readDB();

        const id =
          Number(req.params.id);

        if (!Array.isArray(db[name])) {
          db[name] = [];
        }

        db[name] =
          db[name].filter(
            item =>
              Number(item.id) !== id
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
          error: 'Database error'
        });

      }

    }
  );

}


/* ---------- Admin Collections ---------- */

[
  'programs',
  'events',
  'gallery',
  'documents',
  'donors'
].forEach(crudRoutes);


/* ---------- Submission Tables ---------- */

const submissionTables = {

  volunteers:
    'volunteers',

  members:
    'members',

  contactMessages:
    'contact_messages',

  newsletter:
    'newsletter'

};


/* ---------- Submission Routes ---------- */

function submissionRoutes(name) {

  const table =
    submissionTables[name];

  if (!table) {

    console.error(
      `Unknown submission collection: ${name}`
    );

    return;
  }


  /* Public form submission */

  app.post(
    `/api/${name}`,
    async (req, res) => {

      try {

        const submissionData =
          {
            ...(req.body || {})
          };


        /*
         * Volunteer applications
         * always start as pending.
         */

        if (name === 'volunteers') {

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

          id: row.id

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


  /* Admin read */

  app.get(
    `/api/${name}`,
    requireAdmin,
    async (req, res) => {

      try {

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


  /* Admin delete */

  app.delete(
    `/api/${name}/:id`,
    requireAdmin,
    async (req, res) => {

      try {

        const id =
          Number(req.params.id);


        if (!Number.isInteger(id)) {

          return res.status(400).json({

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
   VOLUNTEER ID SYSTEM
   ========================================================= */


/* ---------- Approve & Issue ID ---------- */

app.post(
  '/api/volunteers/:id/approve',
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);


      if (!Number.isInteger(id)) {

        return res.status(400).json({

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


      if (!result.rows.length) {

        return res.status(404).json({

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
        `NSF-V-${String(row.id).padStart(5, '0')}`;


      const verificationCode =
        data.verificationCode ||
        crypto
          .randomBytes(16)
          .toString('hex');


      const verificationUrl =
        `${PUBLIC_BASE_URL.replace(/\/$/, '')}/verify/volunteer/${verificationCode}`;


      const now =
        new Date().toISOString();


      data.status =
        'active';

      data.volunteerId =
        volunteerId;

      data.verificationCode =
        verificationCode;

      data.verificationUrl =
        verificationUrl;

      data.approvedAt =
        data.approvedAt || now;

      data.issuedAt =
        data.issuedAt || now;

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
            JSON.stringify(data),
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


/* ---------- Reject Volunteer ---------- */

app.post(
  '/api/volunteers/:id/reject',
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);


      if (!Number.isInteger(id)) {

        return res.status(400).json({

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


      if (!result.rows.length) {

        return res.status(404).json({

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
        new Date().toISOString();

      data.revokedAt =
        null;


      const updated =
        await pool.query(

          `UPDATE volunteers
           SET data = $1::jsonb
           WHERE id = $2
           RETURNING id, data, created_at`,

          [
            JSON.stringify(data),
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


/* ---------- Revoke Volunteer ID ---------- */

app.post(
  '/api/volunteers/:id/revoke',
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);


      if (!Number.isInteger(id)) {

        return res.status(400).json({

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


      if (!result.rows.length) {

        return res.status(404).json({

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
        new Date().toISOString();


      const updated =
        await pool.query(

          `UPDATE volunteers
           SET data = $1::jsonb
           WHERE id = $2
           RETURNING id, data, created_at`,

          [
            JSON.stringify(data),
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
          'Could not revoke volunteer ID'

      });

    }

  }
);


/* ---------- Public Verification API ---------- */

app.get(
  '/api/volunteers/verify/:code',
  async (req, res) => {

    try {

      const code =
        String(
          req.params.code || ''
        ).trim();


      if (!code) {

        return res.status(400).json({

          verified:
            false,

          error:
            'Verification code is required'

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


      if (!result.rows.length) {

        return res.status(404).json({

          verified:
            false,

          status:
            'not_found',

          message:
            'Volunteer ID could not be verified'

        });

      }


      const row =
        result.rows[0];


      const data =
        row.data || {};


      const status =
        data.status || 'pending';


      const verified =
        status === 'active';


      res.json({

        verified,

        status,

        volunteerId:
          data.volunteerId || null,

        name:
          data.vName ||
          data.name ||
          '',

        city:
          data.vCity ||
          data.city ||
          '',

        area:
          data.vArea ||
          data.area ||
          '',

        skills:
          data.vSkills ||
          data.skills ||
          '',

        approvedAt:
          data.approvedAt ||
          null,

        issuedAt:
          data.issuedAt ||
          null,

        revokedAt:
          data.revokedAt ||
          null,

        rejectedAt:
          data.rejectedAt ||
          null,

        message:
          verified
            ? 'Volunteer ID is valid and active'
            : `Volunteer ID status: ${status}`

      });


    } catch (error) {

      console.error(
        'VERIFY VOLUNTEER ERROR:',
        error
      );

      res.status(500).json({

        verified:
          false,

        error:
          'Verification service error'

      });

    }

  }
);


/* ---------- Public QR Verification Page ---------- */

app.get(
  '/verify/volunteer/:code',
  (req, res) => {

    const code =
      String(
        req.params.code || ''
      )
      .replace(
        /[^a-zA-Z0-9_-]/g,
        ''
      );


    res.type('html');


    res.send(`<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width, initial-scale=1.0"
>

<title>
Volunteer ID Verification
</title>

<style>

* {
  box-sizing: border-box;
}

body {

  margin: 0;

  min-height: 100vh;

  display: flex;

  align-items: center;

  justify-content: center;

  padding: 20px;

  font-family:
    Arial,
    Helvetica,
    sans-serif;

  background:
    #f1f5f9;

  color:
    #1e293b;

}

.card {

  width: 100%;

  max-width: 520px;

  background:
    white;

  border-radius:
    20px;

  padding:
    30px;

  box-shadow:
    0 10px 40px
    rgba(0,0,0,.12);

}

.logo {

  text-align:
    center;

  font-size:
    30px;

  margin-bottom:
    8px;

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


    if (data.verified) {

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


  function escapeHTML(value) {

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


/* ---------- Website Form Collections ---------- */

[
  'volunteers',
  'members',
  'contactMessages',
  'newsletter'
].forEach(
  submissionRoutes
);


/* ---------- Main Website ---------- */

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


/* ---------- Error Handler ---------- */

app.use(
  (err, req, res, next) => {

    console.error(
      'SERVER ERROR:',
      err
    );

    if (res.headersSent) {
      return next(err);
    }

    res.status(500).json({

      error:
        err.message ||
        'Internal server error'

    });

  }
);


/* ---------- Start Server ---------- */

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
      '======================================'
    );

  }
);
