'use strict';

const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is required. Configure it in your environment; never commit credentials.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: Math.min(5, Math.max(1, Number.parseInt(process.env.PGPOOL_MAX || '3', 10) || 3)),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  ...(process.env.PGSSLMODE === 'require'
    ? { ssl: { rejectUnauthorized: process.env.PGSSL_REJECT_UNAUTHORIZED !== 'false' } }
    : {})
});

pool.on('error', (error) => {
  console.error('Unexpected PostgreSQL pool error:', error.message);
});

const ready = pool.query(`
  CREATE TABLE IF NOT EXISTS nsf_app_state (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`).then(() => pool.query(`
  INSERT INTO nsf_app_state (id, data)
  VALUES (1, '{}'::jsonb)
  ON CONFLICT (id) DO NOTHING
`)).then(() => undefined);

let writeQueue = Promise.resolve();

async function readDB() {
  await ready;
  const result = await pool.query('SELECT data FROM nsf_app_state WHERE id = 1');
  return result.rows[0]?.data && typeof result.rows[0].data === 'object'
    ? result.rows[0].data
    : {};
}

/*
 * The existing CRUD handlers read the complete collection object and then
 * write it back. Serialize writes in this Node process so overlapping admin
 * saves do not overwrite each other. For horizontal scaling, replace this
 * legacy whole-document interface with row-level CRUD operations.
 */
async function writeDB(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new TypeError('writeDB expects a collection object');
  }
  const snapshot = JSON.stringify(data);
  const operation = writeQueue.then(async () => {
    await ready;
    await pool.query(
      'UPDATE nsf_app_state SET data = $1::jsonb, updated_at = NOW() WHERE id = 1',
      [snapshot]
    );
  });
  writeQueue = operation.catch(() => undefined);
  return operation;
}

function nextId(items) {
  if (!Array.isArray(items) || items.length === 0) return 1;
  let max = 0;
  for (const item of items) {
    const id = Number(item?.id);
    if (Number.isSafeInteger(id) && id > max) max = id;
  }
  return max + 1;
}

module.exports = { pool, readDB, writeDB, nextId };
