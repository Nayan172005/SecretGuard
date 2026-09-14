/**
 * Scan Routes — Upload, start scan, get results
 */

const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const scanController = require('../controllers/scanController');

// Configure multer for ZIP uploads
const maxSize = (parseInt(process.env.MAX_UPLOAD_SIZE_MB) || 100) * 1024 * 1024;

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '..', '..', 'uploads');
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const scanId = uuidv4();
    req.scanId = scanId;
    cb(null, `${scanId}.zip`);
  }
});

const fileFilter = (req, file, cb) => {
  // Only allow ZIP files
  if (file.mimetype === 'application/zip' ||
      file.mimetype === 'application/x-zip-compressed' ||
      file.mimetype === 'application/octet-stream' ||
      file.originalname.toLowerCase().endsWith('.zip')) {
    cb(null, true);
  } else {
    cb(new Error('Only ZIP files are allowed'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: maxSize }
});

// POST /api/scans — Upload and start scan
router.post('/', upload.single('repository'), scanController.createScan);

// GET /api/scans — List all scans
router.get('/', scanController.listScans);

// GET /api/scans/:id — Get scan details
router.get('/:id', scanController.getScan);

// GET /api/scans/:id/findings — Get findings for a scan
router.get('/:id/findings', scanController.getScanFindings);

module.exports = router;
