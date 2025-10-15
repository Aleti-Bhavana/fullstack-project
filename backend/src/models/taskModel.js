const db = require('../config/db');

const Task = {
    create: (task, callback) => {
        const { title, description, userId } = task;
        const sql = `INSERT INTO tasks (title, description, userId) VALUES (?, ?, ?)`;
        db.run(sql, [title, description, userId], function(err) {
            callback(err, this.lastID);
        });
    },
    getAll: (callback) => db.all(`SELECT * FROM tasks`, callback),
    getById: (id, callback) => db.get(`SELECT * FROM tasks WHERE id = ?`, [id], callback),
    update: (id, task, callback) => {
        const { title, description } = task;
        db.run(`UPDATE tasks SET title = ?, description = ? WHERE id = ?`, [title, description, id], function(err) {
            callback(err, this.changes);
        });
    },
    delete: (id, callback) => db.run(`DELETE FROM tasks WHERE id = ?`, [id], function(err) {
        callback(err, this.changes);
    })
};

module.exports = Task;
