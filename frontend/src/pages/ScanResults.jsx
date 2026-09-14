/**
 * Scan Results Page — Findings table with severity, detection, and exposure info
 */

import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import { getScan, getScanFindings, getReportUrl } from '../services/api';

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

export default function ScanResults() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('ALL');

  useEffect(() => {
    loadData();
  }, [scanId]);

  async function loadData() {
    try {
      const [scanData, findingsData] = await Promise.all([
        getScan(scanId),
        getScanFindings(scanId),
      ]);
      setScan(scanData);
      setFindings(Array.isArray(findingsData) ? findingsData : []);
    } catch (err) {
      console.error('Failed to load scan results:', err);
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="loading-overlay">
        <div className="spinner"></div>
        <p>Loading scan results...</p>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="empty-state">
        <h3>Scan not found</h3>
        <button className="btn btn-primary" onClick={() => navigate('/')}>Back to Dashboard</button>
      </div>
    );
  }

  const sev = scan.severityCounts || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const sevData = [
    { name: 'Critical', value: sev.CRITICAL, color: SEVERITY_COLORS.CRITICAL },
    { name: 'High', value: sev.HIGH, color: SEVERITY_COLORS.HIGH },
    { name: 'Medium', value: sev.MEDIUM, color: SEVERITY_COLORS.MEDIUM },
    { name: 'Low', value: sev.LOW, color: SEVERITY_COLORS.LOW },
  ].filter(d => d.value > 0);

  const filteredFindings = filter === 'ALL'
    ? findings
    : findings.filter(f => (f.severity || f.severity) === filter);

  const getFindingId = (f) => f.findingId || f.finding_id || f._id;

  return (
    <div className="fade-in">
      <div className="page-header">
        <h2>Scan Results — {scan.repositoryName || 'Unknown'}</h2>
        <p>Scan completed • {findings.length} findings • Risk Score: {(scan.riskScore || 0).toFixed ? (scan.riskScore || 0).toFixed(1) : scan.riskScore}</p>
      </div>

      {/* Summary Stats */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Files Scanned</div>
          <div className="stat-value">{scan.filesScanned || 0}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Lines Analyzed</div>
          <div className="stat-value">{(scan.totalLines || 0).toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Candidates</div>
          <div className="stat-value">{scan.candidatesFound || 0}</div>
        </div>
        <div className="stat-card" style={{ '--stat-accent': '#8b5cf6' }}>
          <div className="stat-label">Reconstructed</div>
          <div className="stat-value" style={{ color: '#8b5cf6' }}>{scan.secretsReconstructed || 0}</div>
        </div>
        <div className="stat-card critical">
          <div className="stat-label">Critical</div>
          <div className="stat-value critical">{sev.CRITICAL}</div>
        </div>
        <div className="stat-card high">
          <div className="stat-label">High</div>
          <div className="stat-value high">{sev.HIGH}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Duration</div>
          <div className="stat-value">{scan.scanDuration ? scan.scanDuration.toFixed(1) + 's' : 'N/A'}</div>
        </div>
      </div>

      {/* Charts + Actions */}
      <div className="charts-grid">
        <div className="card">
          <div className="card-header">
            <span className="card-title">Severity Distribution</span>
          </div>
          {sevData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={sevData} cx="50%" cy="50%" outerRadius={80} innerRadius={40} dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}>
                  {sevData.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : <div className="empty-state"><p>No findings</p></div>}
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">Actions</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <a href={getReportUrl(scanId)} target="_blank" rel="noopener" className="btn btn-primary" style={{ justifyContent: 'center' }}>
              📄 Download PDF Report
            </a>
            <button className="btn btn-secondary" onClick={() => navigate('/scan')}>
              🔍 New Scan
            </button>
            <button className="btn btn-secondary" onClick={() => navigate('/')}>
              📊 Dashboard
            </button>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Findings ({filteredFindings.length})</span>
          <div style={{ display: 'flex', gap: 8 }}>
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
              <button
                key={sev}
                className={`btn ${filter === sev ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setFilter(sev)}
                style={{ padding: '6px 12px', fontSize: 11 }}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {filteredFindings.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Secret Type</th>
                <th>File</th>
                <th>Line</th>
                <th>Detection</th>
                <th>Reconstruction</th>
                <th>Exposure</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.map((f) => (
                <tr key={getFindingId(f)} onClick={() => navigate(`/finding/${getFindingId(f)}`)}>
                  <td>
                    <span className={`severity-badge ${(f.severity || 'medium').toLowerCase()}`}>
                      {f.severity || f.severity}
                    </span>
                  </td>
                  <td style={{ fontWeight: 500 }}>{f.secretType || f.secret_type}</td>
                  <td className="file-path">{(f.filePath || f.file_path || '').split('/').pop()}</td>
                  <td>{f.lineNumber || f.line_number}</td>
                  <td style={{ fontSize: 11 }}>
                    {(f.detectionMethods || f.detection_methods || []).join(', ')}
                  </td>
                  <td>
                    <span className={`severity-badge ${
                      (f.reconstructionStatus || f.reconstruction_status) === 'FULL' ? 'high' :
                      (f.reconstructionStatus || f.reconstruction_status) === 'PARTIAL' ? 'medium' : 'low'
                    }`}>
                      {f.reconstructionStatus || f.reconstruction_status || 'NONE'}
                    </span>
                  </td>
                  <td style={{ fontSize: 12, maxWidth: 150, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {f.exposureType || f.exposure_type || '—'}
                  </td>
                  <td style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
                    {(f.riskScore || f.risk_score || 0).toFixed ? (f.riskScore || f.risk_score || 0).toFixed(1) : (f.riskScore || f.risk_score || 0)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">
            <h3>No findings match the filter</h3>
          </div>
        )}
      </div>
    </div>
  );
}
