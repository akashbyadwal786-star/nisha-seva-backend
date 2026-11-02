'use strict';

const FEATURE_TABLES = Object.freeze({
  passport: 'nsf_student_impact_passports',
  tasks: 'nsf_coordinator_tasks',
  research: 'nsf_ai_field_research',
  map: 'nsf_gram_impact_map',
  tracker: 'nsf_impact_tracker',
  opportunities: 'nsf_seva_opportunity_exchange',
  challenge: 'nsf_impact_challenges',
  voice: 'nsf_voice_seva',
  issues: 'nsf_jan_samasya_timeline',
  scorecard: 'nsf_village_scorecards',
  dna: 'nsf_impact_dna'
});

const REQUIRED_COLUMNS = [
  'id', 'payload', 'status', 'created_by_role',
  'updated_by_role', 'created_at', 'updated_at'
];

const ALLOWED_STATUSES = new Set([
  'draft', 'submitted', 'under_review', 'approved',
  'rejected', 'in_progress', 'completed', 'resolved'
]);

function cleanPayload(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return null;
  }
  const output = {};
  for (const [key, value] of Object.entries(input)) {
    if (!/^[A-Za-z][A-Za-z0-9_]{0,49}$/.test(key)) continue;
    if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) {
      output[key] = typeof value === 'string' ? value.trim().slice(0, 10000) : value;
    }
  }
  return output;
}

module.exports = function registerStudentImpactRoutes({
  app, pool, requireAdmin, publicFormLimiter
}) {
  if (!app || !pool || typeof requireAdmin !== 'function') {
    throw new TypeError('Student Impact routes require app, pool and requireAdmin.');
  }

  // Health check exposes schema readiness only, never records or credentials.
  app.get('/api/student-impact/health', async (req, res) => {
    try {
      const tables = Object.values(FEATURE_TABLES);
      const result = await pool.query(
        `SELECT table_name, column_name
           FROM information_schema.columns
          WHERE table_schema = current_schema()
            AND table_name = ANY($1::text[])`,
        [tables]
      );
      const found = new Map();
      for (const row of result.rows) {
        if (!found.has(row.table_name)) found.set(row.table_name, new Set());
        found.get(row.table_name).add(row.column_name);
      }
      const features = Object.entries(FEATURE_TABLES).map(([feature, table]) => {
        const columns = found.get(table) || new Set();
        const missingColumns = REQUIRED_COLUMNS.filter(column => !columns.has(column));
        return { feature, table, ready: missingColumns.length === 0, missingColumns };
      });
      const readyFeatures = features.filter(item => item.ready).length;
      return res.status(readyFeatures === features.length ? 200 : 503).json({
        success: readyFeatures === features.length,
        service: 'student-impact',
        storage: 'postgresql',
        readyFeatures,
        totalFeatures: features.length,
        features
      });
    } catch (error) {
      console.error('STUDENT IMPACT HEALTH ERROR:', error);
      return res.status(503).json({
        success: false, service: 'student-impact',
        error: 'Could not verify Student Impact database schema.'
      });
    }
  });

  // Public submissions are rate-limited and validated server-side.
  app.post('/api/student-impact/:feature',
    ...(publicFormLimiter ? [publicFormLimiter] : []),
    async (req, res) => {
      const table = FEATURE_TABLES[req.params.feature];
      if (!table) return res.status(404).json({ error: 'Unknown Student Impact feature.' });

      const payload = cleanPayload(req.body);
      if (!payload) return res.status(400).json({ error: 'A valid record is required.' });

      if (req.params.feature === 'challenge') {
        const goal = typeof payload.goal === 'string' ? payload.goal : '';
        const progress = typeof payload.progress === 'string' ? payload.progress : '';
        const day = Number(payload.day);
        if (!goal || goal.length > 300) {
          return res.status(400).json({ error: 'Challenge Goal is required (maximum 300 characters).' });
        }
        if (!Number.isInteger(day) || day < 1 || day > 90) {
          return res.status(400).json({ error: 'Challenge Day must be a whole number from 1 to 90.' });
        }
        if (!progress || progress.length > 10000) {
          return res.status(400).json({ error: 'Progress / Check-in is required (maximum 10,000 characters).' });
        }
        payload.day = day;
      }

      if (!Object.keys(payload).length) {
        return res.status(400).json({ error: 'Record fields cannot be empty.' });
      }

      try {
        const result = await pool.query(
          `INSERT INTO ${table}
             (payload, status, created_by_role, updated_by_role, created_at, updated_at)
           VALUES ($1::jsonb, 'submitted', 'public', 'public', NOW(), NOW())
           RETURNING id, status, created_at`,
          [JSON.stringify(payload)]
        );
        const record = result.rows[0];
        return res.status(201).json({
          success: true,
          id: record.id,
          status: record.status,
          created_at: record.created_at
        });
      } catch (error) {
        console.error(`STUDENT IMPACT CREATE ERROR (${req.params.feature}):`, error);
        return res.status(500).json({ error: 'Record could not be saved. Please try again later.' });
      }
    }
  );

  // Admin-only read. Table identifiers are selected only from the fixed allowlist above.
  app.get('/api/admin/student-impact/:feature', requireAdmin, async (req, res) => {
    const table = FEATURE_TABLES[req.params.feature];
    if (!table) return res.status(404).json({ error: 'Unknown Student Impact feature.' });

    const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 50));
    const status = String(req.query.status || '').trim();
    if (status && !ALLOWED_STATUSES.has(status)) {
      return res.status(400).json({ error: 'Invalid status filter.' });
    }

    try {
      const params = status ? [status, limit] : [limit];
      const where = status ? 'WHERE status = $1' : '';
      const limitParam = status ? '$2' : '$1';
      const result = await pool.query(
        `SELECT id, payload, status, created_by_role, updated_by_role, created_at, updated_at
           FROM ${table}
           ${where}
          ORDER BY created_at DESC, id DESC
          LIMIT ${limitParam}`,
        params
      );
      return res.json({ success: true, records: result.rows });
    } catch (error) {
      console.error(`STUDENT IMPACT LIST ERROR (${req.params.feature}):`, error);
      return res.status(500).json({ error: 'Records could not be loaded.' });
    }
  });

  // Admin-only status update.
  app.patch('/api/admin/student-impact/:feature/:id', requireAdmin, async (req, res) => {
    const table = FEATURE_TABLES[req.params.feature];
    if (!table) return res.status(404).json({ error: 'Unknown Student Impact feature.' });

    const id = String(req.params.id || '').trim();
    const status = String((req.body || {}).status || '').trim();
    if (!/^[A-Za-z0-9_-]{1,100}$/.test(id)) return res.status(400).json({ error: 'Invalid record ID.' });
    if (!ALLOWED_STATUSES.has(status)) return res.status(400).json({ error: 'Invalid status.' });

    try {
      const result = await pool.query(
        `UPDATE ${table}
            SET status = $1, updated_by_role = 'admin', updated_at = NOW()
          WHERE id = $2
          RETURNING id, status, updated_at`,
        [status, id]
      );
      if (!result.rowCount) return res.status(404).json({ error: 'Record not found.' });
      return res.json({ success: true, record: result.rows[0] });
    } catch (error) {
      console.error(`STUDENT IMPACT UPDATE ERROR (${req.params.feature}):`, error);
      return res.status(500).json({ error: 'Record status could not be updated.' });
    }
  });

  // Admin-only delete.
  app.delete('/api/admin/student-impact/:feature/:id', requireAdmin, async (req, res) => {
    const table = FEATURE_TABLES[req.params.feature];
    if (!table) return res.status(404).json({ error: 'Unknown Student Impact feature.' });
    const id = String(req.params.id || '').trim();
    if (!/^[A-Za-z0-9_-]{1,100}$/.test(id)) return res.status(400).json({ error: 'Invalid record ID.' });

    try {
      const result = await pool.query(
        `DELETE FROM ${table} WHERE id = $1 RETURNING id`,
        [id]
      );
      if (!result.rowCount) return res.status(404).json({ error: 'Record not found.' });
      return res.json({ success: true, deletedId: result.rows[0].id });
    } catch (error) {
      console.error(`STUDENT IMPACT DELETE ERROR (${req.params.feature}):`, error);
      return res.status(500).json({ error: 'Record could not be deleted.' });
    }
  });
};
