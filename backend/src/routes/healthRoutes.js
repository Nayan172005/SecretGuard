/**
 * Health Routes
 */
const express = require('express');
const router = express.Router();
const { isDBConnected } = require('../services/database');
const axios = require('axios');

router.get('/', async (req, res) => {
  const pythonUrl = process.env.PYTHON_ENGINE_URL || 'http://localhost:8000';
  let pythonStatus = 'unknown';

  try {
    const resp = await axios.get(`${pythonUrl}/health`, { timeout: 3000 });
    pythonStatus = resp.data.status || 'healthy';
  } catch (e) {
    pythonStatus = 'unavailable';
  }

  res.json({
    status: 'healthy',
    services: {
      backend: 'running',
      database: isDBConnected() ? 'connected' : 'in-memory mode',
      pythonEngine: pythonStatus,
      gemini: process.env.GEMINI_API_KEY ? 'configured' : 'not configured',
    },
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;
