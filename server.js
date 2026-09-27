from pathlib import Path
import re

src_path = Path("/mnt/data/server(2).js")
out_path = Path("/mnt/data/server.js")

src = src_path.read_text(encoding="utf-8")

# 1) Make new volunteer applications start as "pending".
old = """      const result = await pool.query(
        `INSERT INTO ${table} (data)
         VALUES ($1::jsonb)
         RETURNING id, data, created_at`,
        [JSON.stringify(req.body || {})]
      );"""

new = """      // New volunteer applications always start as pending.
      // Other public forms are stored exactly as submitted.
      const submissionData = { ...(req.body || {}) };

      if (name === 'volunteers') {
        submissionData.status = 'pending';
        submissionData.volunteerId = null;
        submissionData.verificationCode = null;
        submissionData.verificationUrl = null;
        submissionData.approvedAt = null;
        submissionData.issuedAt = null;
        submissionData.revokedAt = null;
        submissionData.rejectedAt = null;
      }

      const result = await pool.query(
        `INSERT INTO ${table} (data)
         VALUES ($1::jsonb)
         RETURNING id, data, created_at`,
        [JSON.stringify(submissionData)]
      );"""

if old not in src:
    raise RuntimeError("Volunteer submission block not found.")
src = src.replace(old, new, 1)

# 2) Add volunteer approval / rejection / revocation / public verification routes.
marker = "/* ---------- Website Form Collections ---------- */"

block = r"""
/* ---------- Volunteer ID / Approval System ---------- */

const PUBLIC_BASE_URL =
  process.env.PUBLIC_BASE_URL ||
  'https://nisha-seva-backend.onrender.com';

/*
  Admin: Approve volunteer and issue official ID.
  ID format: NSF-V-00001
  The numeric part comes from the database row ID, so it remains stable.
*/
app.post('/api/volunteers/:id/approve', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({ error: 'Invalid volunteer ID' });
    }

    const result = await pool.query(
      `SELECT id, data, created_at
       FROM volunteers
       WHERE id = $1
       LIMIT 1`,
      [id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: 'Volunteer application not found' });
    }

    const row = result.rows[0];
    const data = { ...(row.data || {}) };

    // Do not issue a different official ID every time admin clicks approve.
    const volunteerId =
      data.volunteerId || `NSF-V-${String(row.id).padStart(5, '0')}`;

    const verificationCode =
      data.verificationCode || crypto.randomBytes(16).toString('hex');

    const verificationUrl =
      `${PUBLIC_BASE_URL.replace(/\/$/, '')}/verify/volunteer/${verificationCode}`;

    const now = new Date().toISOString();

    data.status = 'active';
    data.volunteerId = volunteerId;
    data.verificationCode = verificationCode;
    data.verificationUrl = verificationUrl;
    data.approvedAt = data.approvedAt || now;
    data.issuedAt = data.issuedAt || now;
    data.rejectedAt = null;
    data.revokedAt = null;

    const updated = await pool.query(
      `UPDATE volunteers
       SET data = $1::jsonb
       WHERE id = $2
       RETURNING id, data, created_at`,
      [JSON.stringify(data), id]
    );

    return res.json({
      ok: true,
      message: 'Volunteer approved and ID issued',
      volunteer: {
        id: updated.rows[0].id,
        submittedAt: updated.rows[0].created_at,
        ...(updated.rows[0].data || {})
      },
      volunteerId,
      verificationCode,
      verificationUrl
    });
  } catch (error) {
    console.error('POST /api/volunteers/:id/approve', error);
    return res.status(500).json({
      error: 'Could not approve volunteer'
    });
  }
});


/* Admin: Reject volunteer application */
app.post('/api/volunteers/:id/reject', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({ error: 'Invalid volunteer ID' });
    }

    const result = await pool.query(
      `SELECT id, data, created_at
       FROM volunteers
       WHERE id = $1
       LIMIT 1`,
      [id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: 'Volunteer application not found' });
    }

    const data = { ...(result.rows[0].data || {}) };

    data.status = 'rejected';
    data.rejectedAt = new Date().toISOString();
    data.revokedAt = null;

    const updated = await pool.query(
      `UPDATE volunteers
       SET data = $1::jsonb
       WHERE id = $2
       RETURNING id, data, created_at`,
      [JSON.stringify(data), id]
    );

    return res.json({
      ok: true,
      message: 'Volunteer application rejected',
      volunteer: {
        id: updated.rows[0].id,
        submittedAt: updated.rows[0].created_at,
        ...(updated.rows[0].data || {})
      }
    });
  } catch (error) {
    console.error('POST /api/volunteers/:id/reject', error);
    return res.status(500).json({
      error: 'Could not reject volunteer'
    });
  }
});


/* Admin: Revoke an already issued volunteer ID */
app.post('/api/volunteers/:id/revoke', requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({ error: 'Invalid volunteer ID' });
    }

    const result = await pool.query(
      `SELECT id, data, created_at
       FROM volunteers
       WHERE id = $1
       LIMIT 1`,
      [id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: 'Volunteer application not found' });
    }

    const data = { ...(result.rows[0].data || {}) };

    data.status = 'revoked';
    data.revokedAt = new Date().toISOString();

    const updated = await pool.query(
      `UPDATE volunteers
       SET data = $1::jsonb
       WHERE id = $2
       RETURNING id, data, created_at`,
      [JSON.stringify(data), id]
    );

    return res.json({
      ok: true,
      message: 'Volunteer ID revoked',
      volunteer: {
        id: updated.rows[0].id,
        submittedAt: updated.rows[0].created_at,
        ...(updated.rows[0].data || {})
      }
    });
  } catch (error) {
    console.error('POST /api/volunteers/:id/revoke', error);
    return res.status(500).json({
      error: 'Could not revoke volunteer ID'
    });
  }
});


/* Public: Verify volunteer ID using QR verification code */
app.get('/api/volunteers/verify/:code', async (req, res) => {
  try {
    const code = String(req.params.code || '').trim();

    if (!code) {
      return res.status(400).json({
        verified: false,
        error: 'Verification code is required'
      });
    }

    const result = await pool.query(
      `SELECT id, data, created_at
       FROM volunteers
       WHERE data->>'verificationCode' = $1
       LIMIT 1`,
      [code]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        verified: false,
        status: 'not_found',
        message: 'Volunteer ID could not be verified'
      });
    }

    const row = result.rows[0];
    const data = row.data || {};

    const status = data.status || 'pending';
    const verified = status === 'active';

    return res.json({
      verified,
      status,
      volunteerId: data.volunteerId || null,
      name: data.vName || data.name || '',
      city: data.vCity || data.city || '',
      area: data.vArea || data.area || '',
      skills: data.vSkills || data.skills || '',
      approvedAt: data.approvedAt || null,
      issuedAt: data.issuedAt || null,
      revokedAt: data.revokedAt || null,
      rejectedAt: data.rejectedAt || null,
      message: verified
        ? 'Volunteer ID is valid and active'
        : `Volunteer ID status: ${status}`
    });
  } catch (error) {
    console.error('GET /api/volunteers/verify/:code', error);
    return res.status(500).json({
      verified: false,
      error: 'Verification service error'
    });
  }
});


/* Public verification page opened by QR code */
app.get('/verify/volunteer/:code', (req, res) => {
  const code = String(req.params.code || '');

  const safeCode = code.replace(/[^a-zA-Z0-9_-]/g, '');

  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Volunteer ID Verification - Nisha Seva Foundation</title>
<style>
  *{box-sizing:border-box}
  body{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:20px;
    font-family:Arial,Helvetica,sans-serif;
    background:#f3f6f9;
    color:#1f2937
  }
  .card{
    width:100%;
    max-width:520px;
    background:#fff;
    border-radius:18px;
    padding:28px;
    box-shadow:0 10px 35px rgba(0,0,0,.10)
  }
  h1{margin:0 0 8px;font-size:25px}
  .sub{color:#64748b;margin-bottom:22px}
  .status{
    padding:14px 16px;
    border-radius:12px;
    font-weight:700;
    margin-bottom:20px
  }
  .active{background:#dcfce7;color:#166534}
  .other{background:#fee2e2;color:#991b1b}
  .loading{background:#e2e8f0;color:#334155}
  .row{
    display:flex;
    justify-content:space-between;
    gap:15px;
    border-bottom:1px solid #e5e7eb;
    padding:12px 0
  }
  .label{font-weight:700;color:#475569}
  .value{text-align:right}
  .footer{
    margin-top:20px;
    font-size:13px;
    color:#64748b;
    text-align:center
  }
</style>
</head>
<body>
<div class="card">
  <h1>Nisha Seva Foundation</h1>
  <div class="sub">Volunteer ID Verification</div>
  <div id="status" class="status loading">Verifying ID...</div>
  <div id="details"></div>
  <div class="footer">
    This page verifies the volunteer ID issued by Nisha Seva Foundation.
  </div>
</div>

<script>
(async function(){
  const statusEl = document.getElementById('status');
  const detailsEl = document.getElementById('details');

  try {
    const response = await fetch('/api/volunteers/verify/${safeCode}');
    const data = await response.json();

    if (data.verified) {
      statusEl.className = 'status active';
      statusEl.textContent = '✓ VERIFIED — ACTIVE VOLUNTEER';
    } else {
      statusEl.className = 'status other';
      statusEl.textContent =
        '✕ NOT ACTIVE — ' + String(data.status || 'Not verified').toUpperCase();
    }

    const rows = [
      ['Volunteer ID', data.volunteerId || '—'],
      ['Name', data.name || '—'],
      ['City', data.city || '—'],
      ['Area', data.area || '—'],
      ['Skills', data.skills || '—']
    ];

    detailsEl.innerHTML = rows.map(function(row){
      return '<div class="row">' +
        '<div class="label">' + escapeHtml(row[0]) + '</div>' +
        '<div class="value">' + escapeHtml(row[1]) + '</div>' +
      '</div>';
    }).join('');
  } catch (error) {
    statusEl.className = 'status other';
    statusEl.textContent = 'Verification service unavailable';
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll('&','&amp;')
      .replaceAll('<','&lt;')
      .replaceAll('>','&gt;')
      .replaceAll('"','&quot;')
      .replaceAll("'","&#039;");
  }
})();
</script>
</body>
</html>`);
});


"""

if marker not in src:
    raise RuntimeError("Insertion marker not found.")
src = src.replace(marker, block + marker, 1)

# 3) Add a clear startup message showing the public base URL.
old_start = """  console.log(
    `Admin panel: /admin`
  );"""

new_start = """  console.log(
    `Admin panel: /admin`
  );

  console.log(
    `Volunteer verification: ${PUBLIC_BASE_URL}/verify/volunteer/<code>`
  );"""

if old_start in src:
    src = src.replace(old_start, new_start, 1)

out_path.write_text(src, encoding="utf-8")

print(f"✅ Corrected server.js created: {out_path}")
print(f"Lines: {len(src.splitlines())}")
print("Added: pending status, approve, reject, revoke, verification API, QR verification page.")
/*
|--------------------------------------------------------------------------
| REGISTER WEBSITE FORM COLLECTIONS
|--------------------------------------------------------------------------
*/

[
  'volunteers',
  'members',
  'contactMessages',
  'newsletter'
].forEach(
  submissionRoutes
);


/*
|--------------------------------------------------------------------------
| VOLUNTEER ID / APPROVAL SYSTEM
|--------------------------------------------------------------------------
*/


/*
|--------------------------------------------------------------------------
| APPROVE & ISSUE VOLUNTEER ID
|--------------------------------------------------------------------------
*/

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


      /*
      |----------------------------------------------------------------
      | GET VOLUNTEER
      |----------------------------------------------------------------
      */

      const result =
        await pool.query(

          `SELECT id, data, created_at
           FROM volunteers
           WHERE id = $1
           LIMIT 1`,

          [id]

        );


      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({

          error:
            'Volunteer application not found'

        });

      }


      const row =
        result.rows[0];


      const data =
        {
          ...(row.data || {})
        };


      /*
      |----------------------------------------------------------------
      | CREATE OFFICIAL VOLUNTEER ID
      |----------------------------------------------------------------
      */

      const volunteerId =
        data.volunteerId ||
        `NSF-V-${String(row.id).padStart(5, '0')}`;


      /*
      |----------------------------------------------------------------
      | CREATE VERIFICATION CODE
      |----------------------------------------------------------------
      */

      const verificationCode =
        data.verificationCode ||
        crypto
          .randomBytes(16)
          .toString('hex');


      /*
      |----------------------------------------------------------------
      | VERIFICATION URL
      |----------------------------------------------------------------
      */

      const verificationUrl =
        `${PUBLIC_BASE_URL.replace(/\/$/, '')}/verify/volunteer/${verificationCode}`;


      const now =
        new Date().toISOString();


      /*
      |----------------------------------------------------------------
      | UPDATE VOLUNTEER DATA
      |----------------------------------------------------------------
      */

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


      /*
      |----------------------------------------------------------------
      | SAVE TO DATABASE
      |----------------------------------------------------------------
      */

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


      /*
      |----------------------------------------------------------------
      | RESPONSE
      |----------------------------------------------------------------
      */

      return res.json({

        ok: true,

        message:
          'Volunteer approved and ID issued successfully',

        volunteerId:
          volunteerId,

        verificationCode:
          verificationCode,

        verificationUrl:
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


      return res.status(500).json({

        error:
          'Could not approve volunteer'

      });

    }

  }
);


/*
|--------------------------------------------------------------------------
| REJECT VOLUNTEER
|--------------------------------------------------------------------------
*/

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


      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({

          error:
            'Volunteer application not found'

        });

      }


      const data =
        {
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


/*
|--------------------------------------------------------------------------
| REVOKE VOLUNTEER ID
|--------------------------------------------------------------------------
*/

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


      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({

          error:
            'Volunteer application not found'

        });

      }


      const data =
        {
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


/*
|--------------------------------------------------------------------------
| PUBLIC VOLUNTEER VERIFICATION API
|--------------------------------------------------------------------------
*/

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


      if (
        result.rows.length === 0
      ) {

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

        verified:
          verified,

        status:
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


/*
|--------------------------------------------------------------------------
| PUBLIC QR VERIFICATION PAGE
|--------------------------------------------------------------------------
*/

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

  background: white;

  border-radius: 20px;

  padding: 30px;

  box-shadow:
    0 10px 40px
    rgba(0,0,0,.12);

}


.logo {

  text-align: center;

  font-size: 30px;

  margin-bottom: 8px;

}


h1 {

  text-align: center;

  margin:
    0 0 8px;

}


.subtitle {

  text-align: center;

  color:
    #64748b;

  margin-bottom:
    25px;

}


.status {

  padding: 15px;

  border-radius: 12px;

  text-align: center;

  font-weight: bold;

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

  display: flex;

  justify-content:
    space-between;

  gap: 20px;

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

This page verifies the volunteer ID
issued by Nisha Seva Foundation.

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


/*
|--------------------------------------------------------------------------
| MAIN WEBSITE
|--------------------------------------------------------------------------
*/

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


/*
|--------------------------------------------------------------------------
| LOGO
|--------------------------------------------------------------------------
*/

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


/*
|--------------------------------------------------------------------------
| DONATION QR
|--------------------------------------------------------------------------
*/

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


/*
|--------------------------------------------------------------------------
| ERROR HANDLER
|--------------------------------------------------------------------------
*/

app.use(
  (err, req, res, next) => {

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


/*
|--------------------------------------------------------------------------
| START SERVER
|--------------------------------------------------------------------------
*/

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
      `Verification: ${PUBLIC_BASE_URL}/verify/volunteer/<code>`
    );

    console.log(
      '======================================'
    );

  }
);
