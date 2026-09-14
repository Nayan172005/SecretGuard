/**
 * Finding Routes
 */
const express = require('express');
const router = express.Router();
const findingController = require('../controllers/findingController');

// GET /api/findings/:id — Get finding details
router.get('/:id', findingController.getFinding);

// POST /api/findings/:id/ai-analysis — Generate AI explanation
router.post('/:id/ai-analysis', findingController.generateAIAnalysis);

module.exports = router;
