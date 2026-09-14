/**
 * MongoDB Models — Scan, Finding, Audit
 */

const mongoose = require('mongoose');

// ─── Scan Model ──────────────────────────────────────────────────────────
const scanSchema = new mongoose.Schema({
  scanId: { type: String, required: true, unique: true },
  repositoryName: { type: String, required: true },
  status: {
    type: String,
    enum: ['uploading', 'extracting', 'scanning', 'detecting', 'reconstructing',
           'analyzing', 'scoring', 'ai_analysis', 'generating_report', 'completed', 'failed'],
    default: 'uploading'
  },
  filesScanned: { type: Number, default: 0 },
  totalLines: { type: Number, default: 0 },
  findingsCount: { type: Number, default: 0 },
  candidatesFound: { type: Number, default: 0 },
  secretsReconstructed: { type: Number, default: 0 },
  riskScore: { type: Number, default: 0 },
  severityCounts: {
    CRITICAL: { type: Number, default: 0 },
    HIGH: { type: Number, default: 0 },
    MEDIUM: { type: Number, default: 0 },
    LOW: { type: Number, default: 0 },
  },
  scanDuration: { type: Number, default: 0 },
  aiAnalysisStatus: {
    type: String,
    enum: ['pending', 'in_progress', 'completed', 'unavailable'],
    default: 'pending'
  },
  error: { type: String, default: '' },
}, { timestamps: true });

// ─── Finding Model ───────────────────────────────────────────────────────
const findingSchema = new mongoose.Schema({
  findingId: { type: String, required: true, unique: true },
  scanId: { type: String, required: true, index: true },
  secretType: { type: String, required: true },
  filePath: { type: String, required: true },
  lineNumber: { type: Number, required: true },
  codeContext: { type: String, default: '' },
  maskedSecret: { type: String, default: '' },
  detectionMethods: [{ type: String }],
  confidence: { type: Number, default: 0 },
  entropyScore: { type: Number, default: 0 },
  reconstructionStatus: {
    type: String,
    enum: ['FULL', 'PARTIAL', 'NONE', 'UNRESOLVED'],
    default: 'NONE'
  },
  fragments: [{
    variable: String,
    value: String,
    file: String,
    line: Number,
    resolved: Boolean,
  }],
  reconstructedValueMasked: { type: String, default: '' },
  propagationPath: [{ type: String }],
  propagationGraph: { type: mongoose.Schema.Types.Mixed, default: null },
  exposureSink: { type: mongoose.Schema.Types.Mixed, default: null },
  exposureType: { type: String, default: '' },
  riskScore: { type: Number, default: 0 },
  riskBreakdown: { type: mongoose.Schema.Types.Mixed, default: null },
  severity: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    default: 'LOW'
  },
  aiExplanation: { type: String, default: '' },
  aiRemediation: { type: String, default: '' },
  aiImpact: { type: String, default: '' },
  aiConfidenceAssessment: { type: String, default: '' },
  aiExecutiveSummary: { type: String, default: '' },
  aiAnalysisStatus: {
    type: String,
    enum: ['pending', 'completed', 'unavailable'],
    default: 'pending'
  },
}, { timestamps: true });

// ─── Audit Model ─────────────────────────────────────────────────────────
const auditSchema = new mongoose.Schema({
  action: { type: String, required: true },
  scanId: { type: String, default: '' },
  details: { type: String, default: '' },
  status: { type: String, default: 'success' },
  error: { type: String, default: '' },
}, { timestamps: true });

const Scan = mongoose.model('Scan', scanSchema);
const Finding = mongoose.model('Finding', findingSchema);
const Audit = mongoose.model('Audit', auditSchema);

module.exports = { Scan, Finding, Audit };
