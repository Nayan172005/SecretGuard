/**
 * Scan History Page
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { listScans } from '../services/api';

export default function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    loadScans();
  }, []);

  async function loadScans() {
    try {
      const data = await listScans();
      setScans(Array.isArray(data) ? data : []);
    } catch (err) {
      console.warn('Could not load scans:', err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <h2>Scan History</h2>
        <p>All previous security scans and their results</p>
      </div>

      <div className="card">
        <div className="card-header">
          <span className="card-title">Scans ({scans.length})</span>
          <button className="btn btn-primary" onClick={() => navigate('/scan')}>
            🔍 New Scan
          </button>
        </div>

        {loading ? (
          <div className="loading-overlay">
            <div className="spinner"></div>
            <p>Loading scan history...</p>
          </div>
        ) : scans.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Repository</th>
                <th>Status</th>
                <th>Files</th>
                <th>Findings</th>
                <th>Critical</th>
                <th>High</th>
                <th>Risk Score</th>
                <th>Reconstructed</th>
                <th>Duration</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {scans.map(scan => (
                <tr key={scan.scanId} onClick={() => {
                  if (scan.status === 'completed') navigate(`/results/${scan.scanId}`);
                }}>
                  <td style={{ fontWeight: 600 }}>{scan.repositoryName || 'Unknown'}</td>
                  <td>
                    <span className={`severity-badge ${
                      scan.status === 'completed' ? 'low' :
                      scan.status === 'failed' ? 'critical' : 'medium'
                    }`}>
                      {scan.status}
                    </span>
                  </td>
                  <td>{scan.filesScanned || 0}</td>
                  <td>{scan.findingsCount || 0}</td>
                  <td style={{ color: scan.severityCounts?.CRITICAL > 0 ? 'var(--severity-critical)' : 'var(--text-muted)' }}>
                    {scan.severityCounts?.CRITICAL || 0}
                  </td>
                  <td style={{ color: scan.severityCounts?.HIGH > 0 ? 'var(--severity-high)' : 'var(--text-muted)' }}>
                    {scan.severityCounts?.HIGH || 0}
                  </td>
                  <td>{(scan.riskScore || 0).toFixed ? (scan.riskScore || 0).toFixed(1) : scan.riskScore}</td>
                  <td style={{ color: 'var(--accent-purple)' }}>{scan.secretsReconstructed || 0}</td>
                  <td>{scan.scanDuration ? scan.scanDuration.toFixed(1) + 's' : 'N/A'}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                    {scan.createdAt ? new Date(scan.createdAt).toLocaleDateString() : 'N/A'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">📋</div>
            <h3>No scan history</h3>
            <p>Start your first scan to see results here.</p>
          </div>
        )}
      </div>
    </div>
  );
}
