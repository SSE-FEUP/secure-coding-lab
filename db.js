import sqlite3 from "sqlite3";
sqlite3.verbose();

const dbFile = "./lab.db";
export const db = new sqlite3.Database(dbFile);

// Create minimal schema if missing
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('user','admin')),
      password TEXT NOT NULL
    )
  `);
});

export function query(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

export function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ changes: this.changes, lastID: this.lastID });
    });
  });
}
