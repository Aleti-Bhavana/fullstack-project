// src/models/userModel.js
const db = require('../config/db');
const bcrypt = require('bcrypt');

const User = {
    // Create a new user
    create: ({ username, password, role }, callback) => {
        // Hash the password before storing
        const hashedPassword = bcrypt.hashSync(password, 10);
        const sql = `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`;
        db.run(sql, [username, hashedPassword, role], function(err) {
            callback(err, this.lastID); // Return the new user ID
        });
    },

    // Find a user by username
    findByUsername: (username, callback) => {
        const sql = `SELECT * FROM users WHERE username = ?`;
        db.get(sql, [username], (err, row) => {
            callback(err, row);
        });
    },

    // Find a user by ID (optional, for JWT verification)
    findById: (id, callback) => {
        const sql = `SELECT * FROM users WHERE id = ?`;
        db.get(sql, [id], (err, row) => {
            callback(err, row);
        });
    },

    
    getAll: (callback) => {
        const sql = `SELECT id, username, role FROM users`;
        db.all(sql, [], (err, rows) => {
            callback(err, rows);
        });
    }
};

module.exports = User;
