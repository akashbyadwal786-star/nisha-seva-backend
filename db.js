const mysql = require('mysql2/promise');

const defaultDB = {
  programs: [], events: [], gallery: [], documents: [], donors: [],
  volunteers: [], members: [], contactMessages: [], newsletter: []
};

const requiredDbVars = ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD'];
const missingDbVars = requiredDbVars.filter(key => !process.env[key]);
if (missingDbVars.length) {
  throw new Error(`Missing required MySQL environment variables: ${missingDbVars.join(', ')}`);
}

const rawPool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0,
  connectTimeout: 15000,
  charset: 'utf8mb4'
});

function translateSql(sql) {
  let s = sql
    .replace(/\$\d+::jsonb/gi, '?')
    .replace(/\$\d+/g, '?')
    .replace(/\s+NOT NULL DEFAULT '\{\}'::jsonb/gi, ' NOT NULL')
    .replace(/\bSERIAL\s+PRIMARY\s+KEY\b/gi, 'INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY')
    .replace(/\bJSONB\b/gi, 'JSON')
    .replace(/\bTIMESTAMPTZ\b/gi, 'TIMESTAMP')
    .replace(/DEFAULT\s+NOW\(\)/gi, 'DEFAULT CURRENT_TIMESTAMP')
    .replace(/data->>'verificationCode'/g, "JSON_UNQUOTE(JSON_EXTRACT(data, '$.verificationCode'))");
  return s;
}

function orderedParams(sql, params) {
  const positions = [...sql.matchAll(/\$(\d+)/g)].map(m => Number(m[1]));
  if (!positions.length) return params || [];
  return positions.map(n => (params || [])[n - 1]);
}

const pool = {
  async query(sql, params = []) {
    const originalSql = sql;
    const returningMatch = sql.match(/\s+RETURNING\s+([\w,\s*]+)\s*;?\s*$/i);
    const returning = returningMatch ? returningMatch[1].trim() : null;
    if (returning) sql = sql.slice(0, returningMatch.index);
    const values = orderedParams(originalSql, params);
    sql = translateSql(sql);
    const [result, fields] = await rawPool.query(sql, values);

    if (Array.isArray(result)) {
      return { rows: result, rowCount: result.length, fields };
    }

    let rows = [];
    if (returning) {
      const verb = /^\s*(INSERT|UPDATE|DELETE)\b/i.exec(sql)?.[1]?.toUpperCase();
      const table = /\b(?:INTO|UPDATE|FROM)\s+`?([a-zA-Z0-9_]+)`?/i.exec(sql)?.[1];
      if (verb === 'INSERT' && result.insertId && table) {
        const [found] = await rawPool.query(`SELECT ${returning} FROM \`${table}\` WHERE id = ? LIMIT 1`, [result.insertId]);
        rows = found;
      } else if (verb === 'UPDATE' && table) {
        const whereId = /\bWHERE\s+id\s*=\s*\$(\d+)/i.exec(originalSql);
        if (whereId) {
          const id = (params || [])[Number(whereId[1]) - 1];
          const [found] = await rawPool.query(`SELECT ${returning} FROM \`${table}\` WHERE id = ? LIMIT 1`, [id]);
          rows = found;
        }
      } else if (verb === 'DELETE') {
        // For DELETE RETURNING id, MySQL affectedRows is equivalent for callers that only check rowCount.
        rows = [];
      }
    }
    return { rows, rowCount: result.affectedRows ?? 0, insertId: result.insertId, ...result };
  },
  async getConnection() { return rawPool.getConnection(); },
  async end() { return rawPool.end(); }
};

async function readDB() {
  const [rows] = await rawPool.query('SELECT data FROM app_data WHERE id = 1 LIMIT 1');
  if (!rows.length) {
    throw new Error('app_data row id=1 is missing. Refusing to initialize empty data; verify the imported database before continuing.');
  }
  let data = rows[0].data;
  if (typeof data === 'string') data = JSON.parse(data);
  return data;
}

async function writeDB(data) {
  await rawPool.query(
    `INSERT INTO app_data (id, data) VALUES (1, ?) ON DUPLICATE KEY UPDATE data = VALUES(data)`,
    [JSON.stringify(data)]
  );
  return data;
}

function nextId(collection) {
  return collection.length ? Math.max(...collection.map(i => Number(i.id) || 0)) + 1 : 1;
}

async function ensureTables() {
  const tables = ['volunteers', 'members', 'contact_messages', 'newsletter'];
  for (const table of tables) {
    await rawPool.query(`CREATE TABLE IF NOT EXISTS \`${table}\` (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      data JSON NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
  }
}

module.exports = { readDB, writeDB, nextId, pool, ensureTables, rawPool };
