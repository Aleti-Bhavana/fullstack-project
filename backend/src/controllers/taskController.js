// src/controllers/taskController.js
const Task = require('../models/taskModel');

// Create a new task
const createTask = (req, res, next) => {
    try {
        const { title, description } = req.body;
        if (!title) return res.status(400).json({ message: "Title is required" });

        Task.create({ title, description, userId: req.user.id }, (err, id) => {
            if (err) return next(err);
            res.status(201).json({ id, title, description });
        });
    } catch (err) {
        next(err);
    }
};

// Get all tasks
const getTasks = (req, res, next) => {
    Task.getAll((err, tasks) => {
        if (err) return next(err);
        res.json(tasks);
    });
};

// Update a task
const updateTask = (req, res, next) => {
    const { id } = req.params;
    const { title, description } = req.body;

    Task.update(id, { title, description }, (err, changes) => {
        if (err) return next(err);
        if (changes === 0) return res.status(404).json({ message: "Task not found" });
        res.json({ message: "Task updated" });
    });
};

// Delete a task (Admin only)
const deleteTask = (req, res, next) => {
    const { id } = req.params;

    Task.delete(id, (err, changes) => {
        if (err) return next(err);
        if (changes === 0) return res.status(404).json({ message: "Task not found" });
        res.json({ message: "Task deleted" });
    });
};

module.exports = { createTask, getTasks, updateTask, deleteTask };
