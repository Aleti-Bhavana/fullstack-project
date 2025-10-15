const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database(path.join(__dirname, '../../database/database.sqlite'), (err) => {
    if (err) console.error(err.message);
    else console.log('Connected to SQLite database');
});

module.exports = db;
