/**
 * Report Controller
 * Generates professional PDF security reports using PDFKit.
 */

const PDFDocument = require('pdfkit');
const path = require('path');
const fs = require('fs');
const { Finding } = require('../models');
const { isDBConnected, getInMemoryStore } = require('../services/database');

/**
 * GET /api/reports/:scanId — Generate PDF report
 */
async function generateReport(req, res) {
  try {
    const { scanId } = req.params;

    // Get findings
    let findings;
    let scan;

    if (isDBConnected()) {
      const ScanModel = require('../models').Scan;
      scan = await ScanModel.findOne({ scanId }).lean();
      findings = await Finding.find({ scanId }).sort({ riskScore: -1 }).lean();
    } else {
      const store = getInMemoryStore();
      scan = store.scans.find(s => s.scanId === scanId);
      findings = store.findings
        .filter(f => f.scanId === scanId)
        .sort((a, b) => (b.riskScore || b.risk_score || 0) - (a.riskScore || a.risk_score || 0));
    }

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    // Generate PDF
    const doc = new PDFDocument({ margin: 50, size: 'A4' });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=security-report-${scanId.slice(0, 8)}.pdf`);

    doc.pipe(res);

    // ─── Title Page ──────────────────────────────────────────────────
    doc.fontSize(28).fillColor('#1a1a2e')
       .text('Security Scan Report', { align: 'center' });
    doc.moveDown(0.5);
    doc.fontSize(14).fillColor('#16213e')
       .text('AI-Based Source Code Secret Detector', { align: 'center' });
    doc.fontSize(11).fillColor('#0f3460')
       .text('Program-Flow-Aware Secret Reconstruction and Exposure Analysis', { align: 'center' });
    doc.moveDown(2);

    doc.fontSize(12).fillColor('#333');
    doc.text(`Repository: ${scan.repositoryName || 'Unknown'}`);
    doc.text(`Scan Date: ${new Date(scan.createdAt || Date.now()).toLocaleString()}`);
    doc.text(`Scan ID: ${scanId}`);
    doc.text(`Status: ${scan.status || 'completed'}`);
    doc.moveDown(2);

    // ─── Executive Summary ───────────────────────────────────────────
    doc.fontSize(18).fillColor('#1a1a2e').text('Executive Summary');
    doc.moveDown(0.5);
    doc.fontSize(11).fillColor('#333');

    const sevCounts = scan.severityCounts || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    const totalFindings = findings.length;
    const avgRisk = scan.riskScore || 0;

    doc.text(`Total Findings: ${totalFindings}`);
    doc.text(`Average Risk Score: ${typeof avgRisk === 'number' ? avgRisk.toFixed(1) : avgRisk}/100`);
    doc.text(`Files Scanned: ${scan.filesScanned || 0}`);
    doc.text(`Lines Analyzed: ${scan.totalLines || 0}`);
    doc.text(`Scan Duration: ${scan.scanDuration ? scan.scanDuration.toFixed(2) + 's' : 'N/A'}`);
    doc.text(`Secrets Reconstructed: ${scan.secretsReconstructed || 0}`);
    doc.moveDown(1);

    // Severity breakdown
    doc.fontSize(14).fillColor('#1a1a2e').text('Severity Breakdown');
    doc.moveDown(0.3);
    doc.fontSize(11).fillColor('#e74c3c').text(`  CRITICAL: ${sevCounts.CRITICAL || 0}`);
    doc.fillColor('#e67e22').text(`  HIGH: ${sevCounts.HIGH || 0}`);
    doc.fillColor('#f39c12').text(`  MEDIUM: ${sevCounts.MEDIUM || 0}`);
    doc.fillColor('#27ae60').text(`  LOW: ${sevCounts.LOW || 0}`);
    doc.moveDown(1);

    // ─── Methodology ─────────────────────────────────────────────────
    doc.addPage();
    doc.fontSize(18).fillColor('#1a1a2e').text('Methodology');
    doc.moveDown(0.5);
    doc.fontSize(10).fillColor('#333');
    doc.text('This report was generated using the Program-Flow-Aware Secret Reconstruction and Exposure Analysis methodology. The analysis pipeline consists of:');
    doc.moveDown(0.3);
    doc.text('1. File Scanning — Recursive discovery of source code files');
    doc.text('2. Regex Detection — Pattern matching for known secret formats');
    doc.text('3. Entropy Analysis — Shannon entropy for high-randomness strings');
    doc.text('4. Context Filtering — False positive reduction using code context');
    doc.text('5. Secret Reconstruction — Assembling secrets from code fragments');
    doc.text('6. Dataflow Tracking — Tracing secret propagation through variables');
    doc.text('7. Exposure Sink Analysis — Identifying where secrets are used');
    doc.text('8. Risk Scoring — Transparent, explainable risk assessment');
    doc.moveDown(1);

    // ─── Detailed Findings ──────────────────────────────────────────
    doc.fontSize(18).fillColor('#1a1a2e').text('Detailed Findings');
    doc.moveDown(0.5);

    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      const severity = f.severity || 'MEDIUM';
      const riskScore = f.riskScore || f.risk_score || 0;

      if (doc.y > 650) doc.addPage();

      // Severity color
      const sevColors = { CRITICAL: '#e74c3c', HIGH: '#e67e22', MEDIUM: '#f39c12', LOW: '#27ae60' };
      doc.fontSize(13).fillColor(sevColors[severity] || '#333')
         .text(`Finding #${i + 1}: ${f.secretType || f.secret_type} [${severity}]`);
      doc.moveDown(0.3);
      doc.fontSize(10).fillColor('#333');
      doc.text(`File: ${f.filePath || f.file_path}`);
      doc.text(`Line: ${f.lineNumber || f.line_number}`);
      doc.text(`Risk Score: ${typeof riskScore === 'number' ? riskScore.toFixed(1) : riskScore}/100`);
      doc.text(`Detection: ${(f.detectionMethods || f.detection_methods || []).join(', ')}`);
      doc.text(`Masked Secret: ${f.maskedSecret || f.masked_secret || '****'}`);

      // Reconstruction info
      const reconStatus = f.reconstructionStatus || f.reconstruction_status || 'NONE';
      if (reconStatus !== 'NONE') {
        doc.moveDown(0.2);
        doc.fontSize(10).fillColor('#0f3460').text(`Reconstruction Status: ${reconStatus}`);
        const frags = f.fragments || [];
        if (frags.length > 0) {
          doc.text('Fragments:');
          for (const frag of frags) {
            doc.text(`  • ${frag.variable}: ${frag.value || '****'} (line ${frag.line})`);
          }
        }
      }

      // Propagation path
      const propPath = f.propagationPath || f.propagation_path || [];
      if (propPath.length > 0) {
        doc.moveDown(0.2);
        doc.fontSize(10).fillColor('#0f3460').text('Propagation Path:');
        doc.text(`  ${propPath.join(' → ')}`);
      }

      // Exposure sink
      const sink = f.exposureSink || f.exposure_sink;
      if (sink) {
        doc.moveDown(0.2);
        doc.fontSize(10).fillColor('#e74c3c')
           .text(`Exposure: ${sink.type || sink.sink_type || 'Unknown'} (${sink.risk_level || 'N/A'})`);
        doc.fillColor('#333').text(`  ${sink.description || ''}`);
      }

      // AI Analysis
      const aiExplanation = f.aiExplanation || f.ai_explanation;
      if (aiExplanation) {
        doc.moveDown(0.2);
        doc.fontSize(10).fillColor('#16213e').text('AI Analysis:');
        doc.fillColor('#333').text(aiExplanation.substring(0, 500));
      }

      const aiRemediation = f.aiRemediation || f.ai_remediation;
      if (aiRemediation) {
        doc.moveDown(0.2);
        doc.fontSize(10).fillColor('#16213e').text('Remediation:');
        doc.fillColor('#333').text(aiRemediation.substring(0, 500));
      }

      doc.moveDown(1);
      doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke('#ddd');
      doc.moveDown(0.5);
    }

    // ─── Footer ──────────────────────────────────────────────────────
    doc.addPage();
    doc.fontSize(14).fillColor('#1a1a2e').text('Disclaimer');
    doc.moveDown(0.5);
    doc.fontSize(10).fillColor('#666');
    doc.text('This report is generated by an automated security scanning tool. All credentials shown are masked. This analysis should be supplemented with manual security review. The tool uses static analysis and may not detect all secret patterns.');
    doc.moveDown(1);
    doc.text(`Report generated: ${new Date().toLocaleString()}`);
    doc.text('Tool: AI-Based Source Code Secret Detector v1.0');
    doc.text('Methodology: Program-Flow-Aware Secret Reconstruction and Exposure Analysis');

    doc.end();

  } catch (err) {
    console.error('Report generation error:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Report generation failed: ' + err.message });
    }
  }
}

module.exports = { generateReport };
