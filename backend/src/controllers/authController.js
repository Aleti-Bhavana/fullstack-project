const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const register = (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password || !role) return res.status(400).json({ message: "Missing fields" });

    User.findByUsername(username, (err, user) => {
        if (user) return res.status(400).json({ message: "User already exists" });

        User.create({ username, password, role }, (err, id) => {
            if (err) return res.status(500).json({ message: err.message });
            res.status(201).json({ id, username, role });
        });
    });
};

const login = (req, res) => {
    const { username, password } = req.body;
    User.findByUsername(username, (err, user) => {
        if (!user) return res.status(400).json({ message: "Invalid credentials" });
        const valid = bcrypt.compareSync(password, user.password);
        if (!valid) return res.status(400).json({ message: "Invalid credentials" });

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
};

module.exports = { register, login };
