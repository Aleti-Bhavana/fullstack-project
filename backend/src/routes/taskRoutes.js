// src/routes/taskRoutes.js
const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/authMiddleware');
const { authorize } = require('../middleware/roleMiddleware');
const { createTask, getTasks, updateTask, deleteTask } = require('../controllers/taskController');

// All task routes are protected
router.use(authenticate);

router.get('/', getTasks);
router.post('/', createTask);
router.put('/:id', updateTask);
router.delete('/:id', authorize('Admin'), deleteTask); // Only Admin can delete

module.exports = router;
