// db.js — tiny JSON-file "database". No external DB needed.
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data', 'db.json');

function readDB() {
  if (!fs.existsSync(DB_PATH)) {
    throw new Error('db.json not found at ' + DB_PATH);
  }
  const raw = fs.readFileSync(DB_PATH, 'utf-8');
  return JSON.parse(raw);
}

function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf-8');
}

function nextId(collection) {
  return collection.length ? Math.max(...collection.map(i => i.id)) + 1 : 1;
}

module.exports = { readDB, writeDB, nextId };
