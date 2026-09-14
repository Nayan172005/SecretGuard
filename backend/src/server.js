/**
 * Express Server — Backend Entry Point
 *
 * Orchestrates:
 * - ZIP upload handling
 * - Python detection engine communication
 * - MongoDB persistence (with graceful fallback)
 * - Gemini AI integration (optional)
 * - PDF report generation
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const scanRoutes = require('./routes/scanRoutes');
const findingRoutes = require('./routes/findingRoutes');
const reportRoutes = require('./routes/reportRoutes');
const healthRoutes = require('./routes/healthRoutes');
const { connectDB } = require('./services/database');
const { errorHandler } = require('./middleware/errorHandler');

const app = express();
const PORT = process.env.PORT || 5000;

// ─── Security Middleware ─────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests, please try again later' }
});
app.use('/api/', limiter);

// CORS
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Body parsing with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ─── Temp directories ────────────────────────────────────────────────────
const uploadsDir = path.join(__dirname, '..', 'uploads');
const reportsDir = path.join(__dirname, '..', '..', 'reports');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(reportsDir)) fs.mkdirSync(reportsDir, { recursive: true });

// ─── Routes ──────────────────────────────────────────────────────────────
app.use('/api/health', healthRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/findings', findingRoutes);
app.use('/api/reports', reportRoutes);

// ─── Error Handler ───────────────────────────────────────────────────────
app.use(errorHandler);

// ─── Start Server ────────────────────────────────────────────────────────
async function start() {
  // Try to connect to MongoDB (graceful fallback if unavailable)
  await connectDB();

  app.listen(PORT, () => {
    console.log(`\n🔒 Secret Detector Backend running on port ${PORT}`);
    console.log(`   API: http://localhost:${PORT}/api`);
    console.log(`   Health: http://localhost:${PORT}/api/health`);
    console.log(`   Python Engine: ${process.env.PYTHON_ENGINE_URL || 'http://localhost:8000'}`);
    console.log(`   Gemini: ${process.env.GEMINI_API_KEY ? 'Configured ✓' : 'Not configured (AI analysis unavailable)'}`);
    console.log('');
  });
}

start().catch(err => {
  console.error('Failed to start server:', err);
  // Start anyway even if DB connection fails
  app.listen(PORT, () => {
    console.log(`🔒 Server running on port ${PORT} (DB unavailable, using in-memory mode)`);
  });
});

module.exports = app;
