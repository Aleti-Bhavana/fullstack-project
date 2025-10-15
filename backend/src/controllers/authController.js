// src/controllers/authController.js
const User = require('../models/userModel');
const bcrypt = require('bcrypt');
const { generateToken } = require('../utils/jwtUtils');

// Register a new user
const register = (req, res, next) => {
    try {
        const { username, password, role } = req.body;

        if (!username || !password || !role) {
            return res.status(400).json({ message: "All fields are required" });
        }

        // Check if user exists
        User.findByUsername(username, (err, existingUser) => {
            if (err) return next(err);
            if (existingUser) return res.status(400).json({ message: "User already exists" });

            // Create user
            User.create({ username, password, role }, (err, id) => {
                if (err) return next(err);
                res.status(201).json({ id, username, role });
            });
        });
    } catch (err) {
        next(err);
    }
};

// Login user
const login = (req, res, next) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: "Username and password are required" });
        }

        User.findByUsername(username, (err, user) => {
            if (err) return next(err);
            if (!user) return res.status(400).json({ message: "Invalid credentials" });

            // Compare passwords
            const valid = bcrypt.compareSync(password, user.password);
            if (!valid) return res.status(400).json({ message: "Invalid credentials" });

            // Generate JWT
            const token = generateToken({ id: user.id, role: user.role });
            res.json({ token });
        });
    } catch (err) {
        next(err);
    }
};

module.exports = { register, login };
