const express = require('express');
const router = express.Router();

// Import your route files
const authRoutes = require('./authRoutes');

// Use the route files
router.use('/auth', authRoutes);

// Export the router
module.exports = router;
