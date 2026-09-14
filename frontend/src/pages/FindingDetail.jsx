/**
 * Finding Detail Page — Full analysis evidence with propagation visualization
 * Demonstrates the core novelty: reconstruction + propagation + exposure
 */

import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getFinding, requestAIAnalysis } from '../services/api';

export default function FindingDetail() {
  const { findingId } = useParams();
  const navigate = useNavigate();
  const [finding, setFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [aiLoading, setAiLoading] = useState(false);

  useEffect(() => {
    loadFinding();
  }, [findingId]);

  async function loadFinding() {
    try {
      const data = await getFinding(findingId);
      setFinding(data);
    } catch (err) {
      console.error('Failed to load finding:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleAIAnalysis() {
    setAiLoading(true);
    try {
      const result = await requestAIAnalysis(findingId);
      setFinding(prev => ({
        ...prev,
        aiExplanation: result.explanation || prev.aiExplanation,
        ai_explanation: result.explanation || prev.ai_explanation,
        aiRemediation: result.remediation || prev.aiRemediation,
        ai_remediation: result.remediation || prev.ai_remediation,
        aiImpact: result.impact || prev.aiImpact,
        ai_impact: result.impact || prev.ai_impact,
        aiAnalysisStatus: result.aiAnalysisStatus || 'completed',
        ai_analysis_status: result.aiAnalysisStatus || 'completed',
      }));
    } catch (err) {
      console.error('AI analysis failed:', err);
    } finally {
      setAiLoading(false);
    }
  }

  if (loading) {
    return <div className="loading-overlay"><div className="spinner"></div><p>Loading finding...</p></div>;
  }

  if (!finding) {
    return <div className="empty-state"><h3>Finding not found</h3><button className="btn btn-primary" onClick={() => navigate(-1)}>Go Back</button></div>;
  }

  const f = finding;
  const severity = (f.severity || 'MEDIUM').toUpperCase();
  const riskScore = f.riskScore || f.risk_score || 0;
  const secretType = f.secretType || f.secret_type || 'Unknown';
  const filePath = f.filePath || f.file_path || '';
  const lineNumber = f.lineNumber || f.line_number || 0;
  const maskedSecret = f.maskedSecret || f.masked_secret || '****';
  const detMethods = f.detectionMethods || f.detection_methods || [];
  const reconStatus = f.reconstructionStatus || f.reconstruction_status || 'NONE';
  const fragments = f.fragments || [];
  const reconMasked = f.reconstructedValueMasked || f.reconstructed_value_masked || '';
  const propPath = f.propagationPath || f.propagation_path || [];
  const propGraph = f.propagationGraph || f.propagation_graph;
  const exposureSink = f.exposureSink || f.exposure_sink;
  const exposureType = f.exposureType || f.exposure_type || '';
  const codeContext = f.codeContext || f.code_context || '';
  const entropyScore = f.entropyScore || f.entropy_score || 0;
  const confidence = f.confidence || 0;
  const riskBreakdown = f.riskBreakdown || f.risk_breakdown;
  const aiExplanation = f.aiExplanation || f.ai_explanation || '';
  const aiRemediation = f.aiRemediation || f.ai_remediation || '';
  const aiImpact = f.aiImpact || f.ai_impact || '';
  const aiStatus = f.aiAnalysisStatus || f.ai_analysis_status || 'pending';

  return (
    <div className="fade-in">
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <button className="btn btn-secondary" onClick={() => navigate(-1)} style={{ padding: '8px 14px' }}>
            ← Back
          </button>
          <div>
            <h2>{secretType}</h2>
            <p>{filePath} : line {lineNumber}</p>
          </div>
        </div>
      </div>

      {/* Overview Grid */}
      <div className="finding-detail-grid">
        {/* Risk Score */}
        <div className="detail-section">
          <h3>🎯 Risk Assessment</h3>
          <div className="risk-score-display">
            <div className={`risk-circle ${severity.toLowerCase()}`}>
              {riskScore.toFixed ? riskScore.toFixed(0) : riskScore}
            </div>
            <div>
              <span className={`severity-badge ${severity.toLowerCase()}`}>{severity}</span>
              <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 8 }}>
                Risk Score: {riskScore.toFixed ? riskScore.toFixed(1) : riskScore} / 100
              </p>
            </div>
          </div>
          {riskBreakdown && (
            <div className="risk-breakdown" style={{ marginTop: 16 }}>
              <div className="risk-bar-row">
                <span className="risk-bar-label">Detection Confidence</span>
                <div className="risk-bar-track">
                  <div className="risk-bar-fill" style={{ width: `${(riskBreakdown.detection_confidence || 0) * 4}%` }}></div>
                </div>
                <span className="risk-bar-value">{(riskBreakdown.detection_confidence || 0).toFixed ? (riskBreakdown.detection_confidence || 0).toFixed(1) : riskBreakdown.detection_confidence}/25</span>
              </div>
              <div className="risk-bar-row">
                <span className="risk-bar-label">Secret Sensitivity</span>
                <div className="risk-bar-track">
                  <div className="risk-bar-fill" style={{ width: `${(riskBreakdown.secret_sensitivity || 0) * 4}%` }}></div>
                </div>
                <span className="risk-bar-value">{(riskBreakdown.secret_sensitivity || 0).toFixed ? (riskBreakdown.secret_sensitivity || 0).toFixed(1) : riskBreakdown.secret_sensitivity}/25</span>
              </div>
              <div className="risk-bar-row">
                <span className="risk-bar-label">Exposure Severity</span>
                <div className="risk-bar-track">
                  <div className="risk-bar-fill" style={{ width: `${(riskBreakdown.exposure_severity || 0) * 4}%` }}></div>
                </div>
                <span className="risk-bar-value">{(riskBreakdown.exposure_severity || 0).toFixed ? (riskBreakdown.exposure_severity || 0).toFixed(1) : riskBreakdown.exposure_severity}/25</span>
              </div>
              <div className="risk-bar-row">
                <span className="risk-bar-label">Propagation Certainty</span>
                <div className="risk-bar-track">
                  <div className="risk-bar-fill" style={{ width: `${(riskBreakdown.propagation_certainty || 0) * 4}%` }}></div>
                </div>
                <span className="risk-bar-value">{(riskBreakdown.propagation_certainty || 0).toFixed ? (riskBreakdown.propagation_certainty || 0).toFixed(1) : riskBreakdown.propagation_certainty}/25</span>
              </div>
            </div>
          )}
        </div>

        {/* Detection Info */}
        <div className="detail-section">
          <h3>🔍 Detection Evidence</h3>
          <div className="detail-row"><span className="label">Secret Type</span><span className="value">{secretType}</span></div>
          <div className="detail-row"><span className="label">Masked Secret</span><span className="value mono">{maskedSecret}</span></div>
          <div className="detail-row"><span className="label">Detection Methods</span><span className="value">{detMethods.join(', ')}</span></div>
          <div className="detail-row"><span className="label">Confidence</span><span className="value">{(confidence * 100).toFixed(0)}%</span></div>
          <div className="detail-row"><span className="label">Entropy</span><span className="value">{entropyScore.toFixed ? entropyScore.toFixed(3) : entropyScore}</span></div>
          <div className="detail-row"><span className="label">File</span><span className="value mono" style={{ fontSize: 11 }}>{filePath}</span></div>
          <div className="detail-row"><span className="label">Line</span><span className="value">{lineNumber}</span></div>
        </div>

        {/* ═══ ANALYSIS EVIDENCE — Core Novelty Showcase ═══ */}

        {/* Reconstruction Evidence */}
        <div className="detail-section full-width">
          <h3>🧩 Analysis Evidence — Program-Flow-Aware Secret Reconstruction</h3>

          {/* Detection */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>
              Detection
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {detMethods.map(m => (
                <span key={m} className="severity-badge medium">{m}</span>
              ))}
            </div>
          </div>

          {/* Reconstruction */}
          {reconStatus !== 'NONE' && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>
                Reconstruction ({reconStatus})
              </div>
              <div className="fragments-display">
                {fragments.map((frag, i) => (
                  <React.Fragment key={i}>
                    <div className="fragment-item">
                      <span className="frag-var">{frag.variable}</span>
                      <span style={{ color: 'var(--text-muted)' }}>=</span>
                      <span className="frag-value">{frag.value || '[DYNAMIC]'}</span>
                      <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>Line {frag.line}</span>
                    </div>
                    {i < fragments.length - 1 && (
                      <div style={{ textAlign: 'center', color: 'var(--accent-blue)', fontSize: 18 }}>+</div>
                    )}
                  </React.Fragment>
                ))}
                {reconMasked && (
                  <div className="fragment-result">
                    <span className="result-label">↓ Reconstructed:</span>
                    <span className="result-value">{reconMasked}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Propagation Path */}
          {propPath.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>
                Propagation Path
              </div>
              <div className="propagation-path">
                {propPath.map((step, i) => {
                  const graphNode = propGraph?.nodes?.[i];
                  const isLast = i === propPath.length - 1;
                  const isFirst = i === 0;

                  return (
                    <div className="prop-node" key={i}>
                      <div className="prop-node-indicator">
                        <div className={`prop-node-dot ${isFirst ? 'source' : isLast ? 'sink' : 'intermediate'}`}></div>
                        {!isLast && <div className="prop-node-line"></div>}
                      </div>
                      <div className="prop-node-content">
                        <div className="prop-node-variable">{step}</div>
                        {graphNode && (
                          <>
                            <div className="prop-node-detail">
                              {graphNode.operation} • {graphNode.file}:{graphNode.line}
                            </div>
                            {graphNode.code_snippet && (
                              <div className="prop-node-code">{graphNode.code_snippet}</div>
                            )}
                          </>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Exposure Sink */}
          {exposureSink && (
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>
                Exposure Sink
              </div>
              <div style={{
                background: 'rgba(239, 68, 68, 0.08)',
                border: '1px solid rgba(239, 68, 68, 0.2)',
                borderRadius: 'var(--radius-md)',
                padding: 16,
              }}>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 8 }}>
                  <span className={`severity-badge ${(exposureSink.risk_level || '').toLowerCase() === 'high' ? 'critical' : 'medium'}`}>
                    {exposureSink.risk_level || 'UNKNOWN'}
                  </span>
                  <span style={{ fontWeight: 600, color: 'var(--severity-critical)' }}>
                    {exposureSink.type || exposureType}
                  </span>
                </div>
                <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
                  {exposureSink.description}
                </p>
                {exposureSink.code && (
                  <div className="code-block" style={{ marginTop: 8 }}>{exposureSink.code}</div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Code Context */}
        {codeContext && (
          <div className="detail-section full-width">
            <h3>📝 Code Context</h3>
            <div className="code-block">{codeContext}</div>
          </div>
        )}

        {/* AI Analysis */}
        <div className="detail-section full-width ai-section">
          <h3>🤖 Gemini AI Analysis</h3>
          {aiStatus === 'completed' && aiExplanation ? (
            <div>
              {aiExplanation && (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontWeight: 600, color: 'var(--accent-purple)', marginBottom: 6, fontSize: 13 }}>Explanation</div>
                  <div className="ai-content">{aiExplanation}</div>
                </div>
              )}
              {aiImpact && (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontWeight: 600, color: 'var(--accent-purple)', marginBottom: 6, fontSize: 13 }}>Impact</div>
                  <div className="ai-content">{aiImpact}</div>
                </div>
              )}
              {aiRemediation && (
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--accent-purple)', marginBottom: 6, fontSize: 13 }}>Remediation</div>
                  <div className="ai-content">{aiRemediation}</div>
                </div>
              )}
            </div>
          ) : (
            <div>
              <p style={{ color: 'var(--text-muted)', marginBottom: 12 }}>
                {aiStatus === 'unavailable'
                  ? 'AI analysis unavailable — Gemini API key not configured'
                  : 'AI analysis has not been generated yet'}
              </p>
              <button
                className="btn btn-primary"
                onClick={handleAIAnalysis}
                disabled={aiLoading}
              >
                {aiLoading ? <><div className="spinner" style={{ width: 16, height: 16 }}></div> Analyzing...</> : '🤖 Generate AI Analysis'}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
