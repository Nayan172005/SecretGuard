/**
 * Dashboard Page — Overview of all scans and findings
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { listScans } from '../services/api';

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

export default function Dashboard() {
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

  // Aggregate stats
  const totalScans = scans.length;
  const completedScans = scans.filter(s => s.status === 'completed');
  const totalFindings = completedScans.reduce((sum, s) => sum + (s.findingsCount || 0), 0);
  const totalCritical = completedScans.reduce((sum, s) => sum + (s.severityCounts?.CRITICAL || 0), 0);
  const totalHigh = completedScans.reduce((sum, s) => sum + (s.severityCounts?.HIGH || 0), 0);
  const totalMedium = completedScans.reduce((sum, s) => sum + (s.severityCounts?.MEDIUM || 0), 0);
  const totalLow = completedScans.reduce((sum, s) => sum + (s.severityCounts?.LOW || 0), 0);
  const avgRisk = completedScans.length > 0
    ? completedScans.reduce((sum, s) => sum + (s.riskScore || 0), 0) / completedScans.length
    : 0;

  const severityData = [
    { name: 'Critical', value: totalCritical, color: SEVERITY_COLORS.CRITICAL },
    { name: 'High', value: totalHigh, color: SEVERITY_COLORS.HIGH },
    { name: 'Medium', value: totalMedium, color: SEVERITY_COLORS.MEDIUM },
    { name: 'Low', value: totalLow, color: SEVERITY_COLORS.LOW },
  ].filter(d => d.value > 0);

  const recentScans = scans.slice(0, 5);

  return (
    <div className="fade-in">
      <div className="page-header">
        <h2>Security Dashboard</h2>
        <p>Program-Flow-Aware Secret Reconstruction and Exposure Analysis</p>
      </div>

      {/* Stat Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Total Scans</div>
          <div className="stat-value">{totalScans}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Total Findings</div>
          <div className="stat-value">{totalFindings}</div>
        </div>
        <div className="stat-card critical">
          <div className="stat-label">Critical</div>
          <div className="stat-value critical">{totalCritical}</div>
        </div>
        <div className="stat-card high">
          <div className="stat-label">High</div>
          <div className="stat-value high">{totalHigh}</div>
        </div>
        <div className="stat-card medium">
          <div className="stat-label">Medium</div>
          <div className="stat-value medium">{totalMedium}</div>
        </div>
        <div className="stat-card low">
          <div className="stat-label">Low</div>
          <div className="stat-value low">{totalLow}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Avg Risk Score</div>
          <div className="stat-value">{avgRisk.toFixed(1)}</div>
        </div>
      </div>

      {/* Charts */}
      <div className="charts-grid">
        <div className="card">
          <div className="card-header">
            <span className="card-title">Severity Distribution</span>
          </div>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  innerRadius={50}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {severityData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">
              <p>No findings yet. Start a scan to see data.</p>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">Recent Scan Risk Scores</span>
          </div>
          {completedScans.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={completedScans.slice(0, 8).map(s => ({
                name: (s.repositoryName || 'Unknown').substring(0, 12),
                risk: s.riskScore || 0,
              }))}>
                <XAxis dataKey="name" tick={{ fill: '#8b92a8', fontSize: 11 }} />
                <YAxis tick={{ fill: '#8b92a8', fontSize: 11 }} domain={[0, 100]} />
                <Tooltip
                  contentStyle={{ background: '#1a1f35', border: '1px solid #2a3050', borderRadius: 8 }}
                />
                <Bar dataKey="risk" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state">
              <p>No completed scans yet.</p>
            </div>
          )}
        </div>
      </div>

      {/* Recent Scans */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Recent Scans</span>
          <button className="btn btn-primary" onClick={() => navigate('/scan')}>
            🔍 New Scan
          </button>
        </div>

        {loading ? (
          <div className="loading-overlay">
            <div className="spinner"></div>
            <p>Loading scans...</p>
          </div>
        ) : recentScans.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>Repository</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Risk Score</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.map(scan => (
                <tr key={scan.scanId} onClick={() => {
                  if (scan.status === 'completed') navigate(`/results/${scan.scanId}`);
                }}>
                  <td style={{ fontWeight: 600 }}>{scan.repositoryName || 'Unknown'}</td>
                  <td>
                    <span className={`severity-badge ${scan.status === 'completed' ? 'low' : scan.status === 'failed' ? 'critical' : 'medium'}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td>{scan.findingsCount || 0}</td>
                  <td>{(scan.riskScore || 0).toFixed ? (scan.riskScore || 0).toFixed(1) : scan.riskScore || 0}</td>
                  <td style={{ color: 'var(--text-muted)' }}>
                    {scan.createdAt ? new Date(scan.createdAt).toLocaleString() : 'N/A'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">🔒</div>
            <h3>No scans yet</h3>
            <p>Upload a source code repository to start scanning for secrets.</p>
            <button className="btn btn-primary" onClick={() => navigate('/scan')} style={{ marginTop: 16 }}>
              Start Your First Scan
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
