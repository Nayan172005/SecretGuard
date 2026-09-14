/**
 * Scan Controller
 * Handles ZIP upload, extraction, scan orchestration, and results retrieval.
 */

const path = require('path');
const fs = require('fs');
const AdmZip = require('adm-zip');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const { Scan, Finding, Audit } = require('../models');
const { isDBConnected, getInMemoryStore } = require('../services/database');
const { generateAIExplanations } = require('../services/geminiService');

const PYTHON_URL = process.env.PYTHON_ENGINE_URL || 'http://localhost:8000';
const UPLOADS_DIR = path.join(__dirname, '..', '..', 'uploads');

/**
 * POST /api/scans — Upload ZIP and start scan
 */
async function createScan(req, res) {
  const scanId = req.scanId || uuidv4();

  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded. Please upload a ZIP file.' });
    }

    const repoName = req.body.repositoryName || req.file.originalname.replace('.zip', '');
    const zipPath = req.file.path;

    // Create scan record
    const scanData = {
      scanId,
      repositoryName: repoName,
      status: 'extracting',
      filesScanned: 0,
      findingsCount: 0,
      riskScore: 0,
    };

    if (isDBConnected()) {
      await Scan.create(scanData);
      await Audit.create({ action: 'scan_created', scanId, details: `Repository: ${repoName}` });
    } else {
      scanData.createdAt = new Date().toISOString();
      getInMemoryStore().scans.push(scanData);
    }

    // Extract ZIP safely
    const extractDir = path.join(UPLOADS_DIR, scanId);
    try {
      await safeExtractZip(zipPath, extractDir);
    } catch (extractErr) {
      await updateScanStatus(scanId, 'failed', { error: extractErr.message });
      return res.status(400).json({ error: `ZIP extraction failed: ${extractErr.message}` });
    }

    // Send immediate response with scan ID
    res.status(201).json({
      scanId,
      status: 'scanning',
      message: 'Scan started. Use GET /api/scans/:id to check progress.',
    });

    // Run scan asynchronously
    runScanAsync(scanId, extractDir, repoName, zipPath);

  } catch (err) {
    console.error('Scan creation error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
}

/**
 * Safely extract a ZIP file, preventing path traversal attacks.
 */
async function safeExtractZip(zipPath, destDir) {
  const zip = new AdmZip(zipPath);
  const entries = zip.getEntries();

  if (!fs.existsSync(destDir)) {
    fs.mkdirSync(destDir, { recursive: true });
  }

  const resolvedDest = path.resolve(destDir);

  for (const entry of entries) {
    const entryPath = path.resolve(destDir, entry.entryName);

    // PATH TRAVERSAL PROTECTION: ensure all entries stay within destDir
    if (!entryPath.startsWith(resolvedDest)) {
      throw new Error(`Zip path traversal detected: ${entry.entryName}`);
    }

    if (entry.isDirectory) {
      if (!fs.existsSync(entryPath)) {
        fs.mkdirSync(entryPath, { recursive: true });
      }
    } else {
      const dir = path.dirname(entryPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(entryPath, entry.getData());
    }
  }
}

/**
 * Run the detection scan asynchronously.
 */
async function runScanAsync(scanId, extractDir, repoName, zipPath) {
  try {
    await updateScanStatus(scanId, 'scanning');

    // Call Python detection engine
    const response = await axios.post(`${PYTHON_URL}/scan`, {
      path: extractDir,
      repository_name: repoName,
      scan_id: scanId,
    }, { timeout: 300000 }); // 5 min timeout

    if (!response.data.success) {
      await updateScanStatus(scanId, 'failed', { error: response.data.error });
      return;
    }

    const result = response.data.data;

    // Store findings
    const findings = result.findings || [];

    if (isDBConnected()) {
      for (const f of findings) {
        await Finding.create({
          findingId: f.finding_id,
          scanId,
          secretType: f.secret_type,
          filePath: f.file_path,
          lineNumber: f.line_number,
          codeContext: f.code_context,
          maskedSecret: f.masked_secret,
          detectionMethods: f.detection_methods,
          confidence: f.confidence,
          entropyScore: f.entropy_score,
          reconstructionStatus: f.reconstruction_status,
          fragments: f.fragments,
          reconstructedValueMasked: f.reconstructed_value_masked,
          propagationPath: f.propagation_path,
          propagationGraph: f.propagation_graph,
          exposureSink: f.exposure_sink,
          exposureType: f.exposure_type,
          riskScore: f.risk_score,
          riskBreakdown: f.risk_breakdown,
          severity: f.severity,
        });
      }
    } else {
      for (const f of findings) {
        getInMemoryStore().findings.push({
          ...f,
          scanId,
          findingId: f.finding_id,
        });
      }
    }

    // Update scan with results
    await updateScanStatus(scanId, 'completed', {
      filesScanned: result.files_scanned,
      totalLines: result.total_lines,
      findingsCount: result.findings_count,
      candidatesFound: result.candidates_found,
      secretsReconstructed: result.secrets_reconstructed,
      riskScore: result.average_risk_score,
      severityCounts: result.severity_counts,
      scanDuration: result.scan_duration,
    });

    // Try AI analysis (non-blocking)
    if (process.env.GEMINI_API_KEY && findings.length > 0) {
      try {
        await updateScanStatus(scanId, 'completed', { aiAnalysisStatus: 'in_progress' });
        await generateAIExplanations(scanId, findings);
        await updateScanStatus(scanId, 'completed', { aiAnalysisStatus: 'completed' });
      } catch (aiErr) {
        console.warn('AI analysis failed:', aiErr.message);
        await updateScanStatus(scanId, 'completed', { aiAnalysisStatus: 'unavailable' });
      }
    }

    // Clean up
    try {
      fs.unlinkSync(zipPath);
    } catch (e) { /* ignore cleanup errors */ }

    if (isDBConnected()) {
      await Audit.create({ action: 'scan_completed', scanId, details: `Found ${findings.length} findings` });
    }

  } catch (err) {
    console.error(`Scan ${scanId} failed:`, err.message);
    await updateScanStatus(scanId, 'failed', { error: err.message });
  }
}

async function updateScanStatus(scanId, status, updates = {}) {
  if (isDBConnected()) {
    await Scan.findOneAndUpdate({ scanId }, { status, ...updates });
  } else {
    const store = getInMemoryStore();
    const scan = store.scans.find(s => s.scanId === scanId);
    if (scan) {
      scan.status = status;
      Object.assign(scan, updates);
    }
  }
}

/**
 * GET /api/scans — List all scans
 */
async function listScans(req, res) {
  try {
    if (isDBConnected()) {
      const scans = await Scan.find().sort({ createdAt: -1 }).lean();
      return res.json(scans);
    } else {
      const scans = getInMemoryStore().scans.sort(
        (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
      );
      return res.json(scans);
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

/**
 * GET /api/scans/:id — Get scan details
 */
async function getScan(req, res) {
  try {
    const { id } = req.params;
    let scan;

    if (isDBConnected()) {
      scan = await Scan.findOne({ scanId: id }).lean();
    } else {
      scan = getInMemoryStore().scans.find(s => s.scanId === id);
    }

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    res.json(scan);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

/**
 * GET /api/scans/:id/findings — Get findings for a scan
 */
async function getScanFindings(req, res) {
  try {
    const { id } = req.params;
    let findings;

    if (isDBConnected()) {
      findings = await Finding.find({ scanId: id }).sort({ riskScore: -1 }).lean();
    } else {
      findings = getInMemoryStore().findings
        .filter(f => f.scanId === id)
        .sort((a, b) => (b.riskScore || b.risk_score || 0) - (a.riskScore || a.risk_score || 0));
    }

    res.json(findings);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

module.exports = { createScan, listScans, getScan, getScanFindings };
