'use strict';

/**
 * Student Impact Suite routes.
 * Table names are fixed in this whitelist; request input is never used as SQL identifiers.
 */
module.exports = function registerStudentImpactRoutes({ app, pool, requireAdmin, publicFormLimiter }) {
  const tables = {
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
  };
  const statuses = new Set([
    'draft', 'submitted', 'under_review', 'approved', 'rejected',
    'in_progress', 'completed', 'resolved'
  ]);
  const getTable = feature => tables[String(feature || '')] || null;
  const validPayload = payload => payload && typeof payload === 'object' && !Array.isArray(payload);
  const jsonPayload = payload => {
    const json = JSON.stringify(payload);
    if (Buffer.byteLength(json, 'utf8') > 20480) return null;
    return json;
  };

  app.get('/api/student-impact/health', (req, res) => {
    res.set('Cache-Control', 'no-store');
    return res.json({ success: true, service: 'student-impact', storage: 'postgresql', features: Object.keys(tables) });
  });

  app.post('/api/student-impact/:feature', publicFormLimiter, async (req, res) => {
    const table = getTable(req.params.feature);
    if (!table) return res.status(404).json({ error: 'Unknown Student Impact feature.' });
    if (!validPayload(req.body)) return res.status(400).json({ error: 'Payload must be a JSON object.' });
    const payload = jsonPayload(req.body);
    if (payload === null) return res.status(413).json({ error: 'Payload exceeds the 20 KB limit.' });
    try {
      const result = await pool.query(
        'INSERT INTO ' + table + ' (payload, status, created_by_role, updated_by_role) VALUES ($1::jsonb, $2, $3, $4) RETURNING id, status, created_at',
        [payload, 'submitted', 'public', 'public']
      );
      return res.status(201).json({ success: true, record: result.rows[0] });
    } catch (error) {
      console.error('STUDENT IMPACT SUBMIT ERROR:', error);
      return res.status(500).json({ error: 'Submission could not be saved.' });
    }
  });

  app.get('/api/admin/student-impact/:feature', requireAdmin, async (req, res) => {
    const table = getTable(req.params.feature);
    if (!table) return res.status(404).json({ error: 'Unknown Student Impact feature.' });
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));
    const values = [];
    let where = '';
    if (req.query.status) {
      if (!statuses.has(String(req.query.status))) return res.status(400).json({ error: 'Invalid status.' });
      values.push(String(req.query.status));
      where = ' WHERE status = $1';
    }
    values.push(limit);
    try {
      const result = await pool.query(
        'SELECT id, payload, status, created_by_role, updated_by_role, created_at, updated_at FROM ' + table + where + ' ORDER BY created_at DESC LIMIT $' + values.length,
        values
      );
      res.set('Cache-Control', 'no-store');
      return res.json({ success: true, records: result.rows });
    } catch (error) {
      console.error('STUDENT IMPACT LIST ERROR:', error);
      return res.status(500).json({ error: 'Records could not be loaded.' });
    }
  });

  app.patch('/api/admin/student-impact/:feature/:id', requireAdmin, async (req, res) => {
    const table = getTable(req.params.feature);
    if (!table) return res.status(404).json({ error: 'Unknown Student Impact feature.' });
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid record ID.' });
    const body = req.body || {};
    const updates = [];
    const values = [];
    if (Object.prototype.hasOwnProperty.call(body, 'payload')) {
      if (!validPayload(body.payload)) return res.status(400).json({ error: 'Payload must be a JSON object.' });
      const payload = jsonPayload(body.payload);
      if (payload === null) return res.status(413).json({ error: 'Payload exceeds the 20 KB limit.' });
      values.push(payload);
      updates.push('payload = $' + values.length + '::jsonb');
    }
    if (Object.prototype.hasOwnProperty.call(body, 'status')) {
      if (!statuses.has(String(body.status))) return res.status(400).json({ error: 'Invalid status.' });
      values.push(String(body.status));
      updates.push('status = $' + values.length);
    }
    if (!updates.length) return res.status(400).json({ error: 'Provide payload or status to update.' });
    values.push('admin');
    updates.push('updated_by_role = $' + values.length);
    updates.push('updated_at = NOW()');
    values.push(id);
    try {
      const result = await pool.query(
        'UPDATE ' + table + ' SET ' + updates.join(', ') + ' WHERE id = $' + values.length + ' RETURNING id, status, updated_at',
        values
      );
      if (!result.rowCount) return res.status(404).json({ error: 'Record not found.' });
      return res.json({ success: true, record: result.rows[0] });
    } catch (error) {
      console.error('STUDENT IMPACT UPDATE ERROR:', error);
      return res.status(500).json({ error: 'Record could not be updated.' });
    }
  });

  app.delete('/api/admin/student-impact/:feature/:id', requireAdmin, async (req, res) => {
    const table = getTable(req.params.feature);
    if (!table) return res.status(404).json({ error: 'Unknown Student Impact feature.' });
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid record ID.' });
    try {
      const result = await pool.query('DELETE FROM ' + table + ' WHERE id = $1 RETURNING id', [id]);
      if (!result.rowCount) return res.status(404).json({ error: 'Record not found.' });
      return res.json({ success: true, deletedId: result.rows[0].id });
    } catch (error) {
      console.error('STUDENT IMPACT DELETE ERROR:', error);
      return res.status(500).json({ error: 'Record could not be deleted.' });
    }
  });
};
