const { Pool } = require('pg');

const defaultDB = {
  programs: [],
  events: [],
  gallery: [],
  documents: [],
  donors: [],
  volunteers: [],
  members: [],
  contactMessages: [],
  newsletter: []
};

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function readDB() {
  const result = await pool.query(
    'SELECT data FROM app_data WHERE id = true'
  );

  if (!result.rows.length) {
    await writeDB(defaultDB);
    return defaultDB;
  }

  return result.rows[0].data;
}

async function writeDB(data) {
  await pool.query(
    `INSERT INTO app_data (id, data)
     VALUES (true, $1::jsonb)
     ON CONFLICT (id)
     DO UPDATE SET data = EXCLUDED.data`,
    [JSON.stringify(data)]
  );

  return data;
}

function nextId(collection) {
  return collection.length
    ? Math.max(...collection.map(i => Number(i.id) || 0)) + 1
    : 1;
}

module.exports = {
  readDB,
  writeDB,
  nextId
};
