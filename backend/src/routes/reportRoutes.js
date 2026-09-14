/**
 * Report Routes
 */
const express = require('express');
const router = express.Router();
const reportController = require('../controllers/reportController');

// GET /api/reports/:scanId — Generate/download PDF report
router.get('/:scanId', reportController.generateReport);

module.exports = router;
