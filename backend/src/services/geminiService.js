/**
 * Gemini AI Service
 *
 * Integrates with Google Gemini API for:
 * - Security explanations
 * - Impact analysis
 * - Remediation recommendations
 * - Executive summaries
 *
 * IMPORTANT: Gemini only receives masked/minimal finding data.
 * Complete secrets and full repository code are NEVER sent.
 * If GEMINI_API_KEY is not set, all functions gracefully return
 * "AI analysis unavailable" without breaking the scan.
 */

const { GoogleGenerativeAI } = require('@google/generative-ai');
const { Finding } = require('../models');
const { isDBConnected, getInMemoryStore } = require('../services/database');

let genAI = null;
let model = null;

function initGemini() {
  if (!process.env.GEMINI_API_KEY) {
    console.log('⚠️  GEMINI_API_KEY not set — AI analysis unavailable');
    return false;
  }
  try {
    genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    model = genAI.getGenerativeModel({ model: 'gemini-3.6-flash' });
    return true;
  } catch (err) {
    console.error('Failed to initialize Gemini:', err.message);
    return false;
  }
}

/**
 * Analyze a single finding with Gemini.
 * Sends only masked/minimal information — never complete secrets.
 */
async function analyzeWithGemini(finding) {
  if (!model && !initGemini()) {
    return {
      explanation: 'AI analysis unavailable — GEMINI_API_KEY not configured',
      remediation: 'AI analysis unavailable',
      impact: 'AI analysis unavailable',
      confidenceAssessment: 'AI analysis unavailable',
      executiveSummary: 'AI analysis unavailable',
    };
  }

  // Build a safe prompt with ONLY masked/minimal data
  const prompt = buildAnalysisPrompt(finding);

  try {
    const result = await model.generateContent(prompt);
    const response = result.response.text();

    // Parse structured response
    return parseAIResponse(response);
  } catch (err) {
    console.error('Gemini API error:', err.message);
    return {
      explanation: `AI analysis error: ${err.message}`,
      remediation: 'AI analysis unavailable',
      impact: 'AI analysis unavailable',
      confidenceAssessment: 'AI analysis unavailable',
      executiveSummary: 'AI analysis unavailable',
    };
  }
}

/**
 * Build a safe analysis prompt — NEVER include complete secrets.
 */
function buildAnalysisPrompt(finding) {
  const f = finding;
  const secretType = f.secretType || f.secret_type || 'Unknown';
  const severity = f.severity || 'MEDIUM';
  const maskedSecret = f.maskedSecret || f.masked_secret || '****';
  const filePath = f.filePath || f.file_path || 'unknown';
  const lineNumber = f.lineNumber || f.line_number || 0;
  const detectionMethods = f.detectionMethods || f.detection_methods || [];
  const reconstructionStatus = f.reconstructionStatus || f.reconstruction_status || 'NONE';
  const propagationPath = f.propagationPath || f.propagation_path || [];
  const exposureSink = f.exposureSink || f.exposure_sink;
  const riskScore = f.riskScore || f.risk_score || 0;
  const codeContext = (f.codeContext || f.code_context || '').substring(0, 300);

  return `You are a cybersecurity expert analyzing a secret detection finding.
Analyze the following finding and provide a structured security assessment.

FINDING DETAILS:
- Secret Type: ${secretType}
- Severity: ${severity}
- Risk Score: ${riskScore}/100
- Masked Secret: ${maskedSecret}
- File: ${filePath}
- Line: ${lineNumber}
- Detection Methods: ${detectionMethods.join(', ')}
- Reconstruction Status: ${reconstructionStatus}
- Propagation Path: ${propagationPath.join(' → ') || 'None'}
- Exposure Sink: ${exposureSink ? (exposureSink.type || exposureSink.sink_type || 'Unknown') : 'None identified'}
${exposureSink ? `- Exposure Description: ${exposureSink.description || ''}` : ''}

CODE CONTEXT (surrounding lines, masked):
${codeContext}

Please provide your analysis in the following EXACT format:

EXPLANATION:
[Explain what this finding means and why it was detected]

IMPACT:
[Describe the potential security impact if this secret is exposed]

REMEDIATION:
[Provide specific, actionable remediation steps with code examples]

CONFIDENCE:
[Assess whether this is likely a true positive and why]

EXECUTIVE_SUMMARY:
[One paragraph executive summary suitable for a security report]

Important: Do not include or attempt to reconstruct any actual secret values.`;
}

/**
 * Parse the structured AI response into sections.
 */
function parseAIResponse(text) {
  const sections = {
    explanation: '',
    impact: '',
    remediation: '',
    confidenceAssessment: '',
    executiveSummary: '',
  };

  const markers = [
    { key: 'explanation', pattern: /EXPLANATION:\s*([\s\S]*?)(?=IMPACT:|$)/i },
    { key: 'impact', pattern: /IMPACT:\s*([\s\S]*?)(?=REMEDIATION:|$)/i },
    { key: 'remediation', pattern: /REMEDIATION:\s*([\s\S]*?)(?=CONFIDENCE:|$)/i },
    { key: 'confidenceAssessment', pattern: /CONFIDENCE:\s*([\s\S]*?)(?=EXECUTIVE_SUMMARY:|$)/i },
    { key: 'executiveSummary', pattern: /EXECUTIVE_SUMMARY:\s*([\s\S]*?)$/i },
  ];

  for (const { key, pattern } of markers) {
    const match = text.match(pattern);
    if (match) {
      sections[key] = match[1].trim();
    }
  }

  // If parsing failed, put everything in explanation
  if (!sections.explanation && text) {
    sections.explanation = text.trim();
  }

  return sections;
}

/**
 * Generate AI explanations for all findings in a scan.
 * Only processes high-confidence findings to minimize API calls.
 */
async function generateAIExplanations(scanId, findings) {
  if (!model && !initGemini()) return;

  // Only analyze findings with risk score >= 30 (skip LOW findings)
  const significantFindings = findings.filter(f => {
    const score = f.riskScore || f.risk_score || 0;
    return score >= 30;
  });

  // Limit to top 10 findings to avoid excessive API calls
  const toAnalyze = significantFindings.slice(0, 10);

  for (const finding of toAnalyze) {
    try {
      const aiResult = await analyzeWithGemini(finding);
      const findingId = finding.findingId || finding.finding_id;

      if (isDBConnected()) {
        await Finding.findOneAndUpdate({ findingId }, {
          aiExplanation: aiResult.explanation,
          aiRemediation: aiResult.remediation,
          aiImpact: aiResult.impact,
          aiConfidenceAssessment: aiResult.confidenceAssessment,
          aiExecutiveSummary: aiResult.executiveSummary,
          aiAnalysisStatus: 'completed',
        });
      } else {
        const store = getInMemoryStore();
        const f = store.findings.find(f =>
          (f.findingId || f.finding_id) === findingId
        );
        if (f) {
          f.aiExplanation = f.ai_explanation = aiResult.explanation;
          f.aiRemediation = f.ai_remediation = aiResult.remediation;
          f.aiImpact = f.ai_impact = aiResult.impact;
          f.aiConfidenceAssessment = f.ai_confidence_assessment = aiResult.confidenceAssessment;
          f.aiExecutiveSummary = f.ai_executive_summary = aiResult.executiveSummary;
          f.aiAnalysisStatus = f.ai_analysis_status = 'completed';
        }
      }

      // Small delay between API calls
      await new Promise(r => setTimeout(r, 500));
    } catch (err) {
      console.warn(`AI analysis failed for finding ${finding.findingId || finding.finding_id}:`, err.message);
    }
  }
}

/**
 * Generate an executive summary for the entire scan using Gemini.
 */
async function generateExecutiveSummary(scanData) {
  if (!model && !initGemini()) {
    return 'AI executive summary unavailable — GEMINI_API_KEY not configured';
  }

  const prompt = `You are a cybersecurity expert. Generate a brief executive summary for this security scan:

Repository: ${scanData.repositoryName || 'Unknown'}
Files Scanned: ${scanData.filesScanned || 0}
Total Findings: ${scanData.findingsCount || 0}
Critical: ${scanData.severityCounts?.CRITICAL || 0}
High: ${scanData.severityCounts?.HIGH || 0}
Medium: ${scanData.severityCounts?.MEDIUM || 0}
Low: ${scanData.severityCounts?.LOW || 0}
Secrets Reconstructed from Fragments: ${scanData.secretsReconstructed || 0}
Average Risk Score: ${scanData.riskScore || 0}

Write a 2-3 paragraph executive summary suitable for a security report. Focus on the most critical risks found.`;

  try {
    const result = await model.generateContent(prompt);
    return result.response.text();
  } catch (err) {
    return `AI executive summary unavailable: ${err.message}`;
  }
}

module.exports = { analyzeWithGemini, generateAIExplanations, generateExecutiveSummary };
