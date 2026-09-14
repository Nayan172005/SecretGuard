/**
 * Finding Controller
 * Handles individual finding retrieval and AI analysis generation.
 */

const { Finding, Audit } = require('../models');
const { isDBConnected, getInMemoryStore } = require('../services/database');
const { analyzeWithGemini } = require('../services/geminiService');

/**
 * GET /api/findings/:id — Get finding details
 */
async function getFinding(req, res) {
  try {
    const { id } = req.params;
    let finding;

    if (isDBConnected()) {
      finding = await Finding.findOne({ findingId: id }).lean();
    } else {
      finding = getInMemoryStore().findings.find(
        f => (f.findingId || f.finding_id) === id
      );
    }

    if (!finding) {
      return res.status(404).json({ error: 'Finding not found' });
    }

    res.json(finding);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

/**
 * POST /api/findings/:id/ai-analysis — Generate Gemini explanation
 */
async function generateAIAnalysis(req, res) {
  try {
    const { id } = req.params;
    let finding;

    if (isDBConnected()) {
      finding = await Finding.findOne({ findingId: id }).lean();
    } else {
      finding = getInMemoryStore().findings.find(
        f => (f.findingId || f.finding_id) === id
      );
    }

    if (!finding) {
      return res.status(404).json({ error: 'Finding not found' });
    }

    if (!process.env.GEMINI_API_KEY) {
      return res.json({
        ...finding,
        aiAnalysisStatus: 'unavailable',
        aiExplanation: 'AI analysis unavailable — GEMINI_API_KEY not configured',
      });
    }

    const aiResult = await analyzeWithGemini(finding);

    // Update finding with AI analysis
    if (isDBConnected()) {
      await Finding.findOneAndUpdate({ findingId: id }, {
        aiExplanation: aiResult.explanation,
        aiRemediation: aiResult.remediation,
        aiImpact: aiResult.impact,
        aiConfidenceAssessment: aiResult.confidenceAssessment,
        aiExecutiveSummary: aiResult.executiveSummary,
        aiAnalysisStatus: 'completed',
      });
    } else {
      const store = getInMemoryStore();
      const f = store.findings.find(f => (f.findingId || f.finding_id) === id);
      if (f) {
        f.aiExplanation = f.ai_explanation = aiResult.explanation;
        f.aiRemediation = f.ai_remediation = aiResult.remediation;
        f.aiImpact = f.ai_impact = aiResult.impact;
        f.aiConfidenceAssessment = f.ai_confidence_assessment = aiResult.confidenceAssessment;
        f.aiExecutiveSummary = f.ai_executive_summary = aiResult.executiveSummary;
        f.aiAnalysisStatus = f.ai_analysis_status = 'completed';
      }
    }

    res.json({
      findingId: id,
      aiAnalysisStatus: 'completed',
      ...aiResult,
    });

  } catch (err) {
    console.error('AI analysis error:', err);
    res.status(500).json({
      error: 'AI analysis failed',
      aiAnalysisStatus: 'unavailable',
      message: err.message,
    });
  }
}

module.exports = { getFinding, generateAIAnalysis };
