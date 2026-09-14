/**
 * New Scan Page — Upload ZIP and monitor scan progress
 */

import React, { useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { uploadAndScan, getScan } from '../services/api';

const SCAN_STAGES = [
  { key: 'uploading', label: 'Uploading repository' },
  { key: 'extracting', label: 'Extracting ZIP archive' },
  { key: 'scanning', label: 'Scanning files' },
  { key: 'detecting', label: 'Detecting secret candidates' },
  { key: 'reconstructing', label: 'Reconstructing fragmented secrets' },
  { key: 'analyzing', label: 'Program-flow analysis' },
  { key: 'scoring', label: 'Risk scoring' },
  { key: 'ai_analysis', label: 'AI analysis (Gemini)' },
  { key: 'generating_report', label: 'Generating report' },
  { key: 'completed', label: 'Scan completed' },
];

export default function NewScan() {
  const [file, setFile] = useState(null);
  const [repoName, setRepoName] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [currentStage, setCurrentStage] = useState('');
  const [error, setError] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef(null);
  const navigate = useNavigate();

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile && droppedFile.name.endsWith('.zip')) {
      setFile(droppedFile);
      setRepoName(droppedFile.name.replace('.zip', ''));
      setError('');
    } else {
      setError('Please upload a ZIP file');
    }
  }, []);

  const handleFileSelect = (e) => {
    const selected = e.target.files[0];
    if (selected) {
      setFile(selected);
      setRepoName(selected.name.replace('.zip', ''));
      setError('');
    }
  };

  const startScan = async () => {
    if (!file) return;

    setScanning(true);
    setError('');
    setCurrentStage('uploading');

    try {
      // Upload and start scan
      const result = await uploadAndScan(file, repoName);
      setScanId(result.scanId);
      setCurrentStage('scanning');

      // Poll for scan status
      await pollScanStatus(result.scanId);

    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Scan failed');
      setScanning(false);
    }
  };

  const pollScanStatus = async (id) => {
    const maxAttempts = 120; // 2 minutes
    for (let i = 0; i < maxAttempts; i++) {
      try {
        await new Promise(r => setTimeout(r, 1000));
        const scan = await getScan(id);

        setCurrentStage(scan.status);

        if (scan.status === 'completed') {
          setScanning(false);
          // Auto-navigate to results
          setTimeout(() => navigate(`/results/${id}`), 1000);
          return;
        }

        if (scan.status === 'failed') {
          setError(scan.error || 'Scan failed');
          setScanning(false);
          return;
        }
      } catch (err) {
        // Continue polling on transient errors
      }
    }
    setError('Scan timed out');
    setScanning(false);
  };

  const getStageStatus = (stageKey) => {
    const stageIndex = SCAN_STAGES.findIndex(s => s.key === stageKey);
    const currentIndex = SCAN_STAGES.findIndex(s => s.key === currentStage);

    if (currentStage === 'completed') return 'completed';
    if (stageIndex < currentIndex) return 'completed';
    if (stageIndex === currentIndex) return 'active';
    return 'pending';
  };

  return (
    <div className="fade-in">
      <div className="page-header">
        <h2>New Security Scan</h2>
        <p>Upload a ZIP repository for secret detection and exposure analysis</p>
      </div>

      {!scanning && !scanId && (
        <>
          {/* Upload Zone */}
          <div
            className={`upload-zone ${dragOver ? 'drag-over' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <div className="upload-icon">📁</div>
            <h3>{file ? file.name : 'Drop ZIP Repository Here'}</h3>
            <p>
              {file
                ? `${(file.size / 1024 / 1024).toFixed(2)} MB — Click "Start Scan" to begin`
                : 'or click to browse — ZIP files only, max 100MB'}
            </p>
            <input
              ref={fileInputRef}
              type="file"
              accept=".zip"
              onChange={handleFileSelect}
              style={{ display: 'none' }}
            />
          </div>

          {file && (
            <div className="card" style={{ marginTop: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <div style={{ flex: 1 }}>
                  <label style={{ fontSize: 13, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
                    Repository Name
                  </label>
                  <input
                    type="text"
                    value={repoName}
                    onChange={(e) => setRepoName(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '10px 14px',
                      background: 'var(--bg-input)',
                      border: '1px solid var(--border-default)',
                      borderRadius: 'var(--radius-sm)',
                      color: 'var(--text-primary)',
                      fontFamily: 'var(--font-sans)',
                      fontSize: 14,
                      outline: 'none',
                    }}
                  />
                </div>
                <button
                  className="btn btn-primary"
                  onClick={startScan}
                  style={{ marginTop: 22, padding: '12px 28px', fontSize: 15 }}
                >
                  🚀 Start Scan
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Scan Progress */}
      {scanning && (
        <div className="card" style={{ marginTop: 20 }}>
          <div className="card-header">
            <span className="card-title">Scan Progress — {repoName}</span>
            <div className="spinner"></div>
          </div>
          <div className="scan-progress">
            {SCAN_STAGES.map((stage) => {
              const status = getStageStatus(stage.key);
              return (
                <div key={stage.key} className={`progress-step ${status}`}>
                  <div className="step-icon">
                    {status === 'completed' ? '✓' : status === 'active' ? '●' : '○'}
                  </div>
                  <span>{stage.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Completed */}
      {currentStage === 'completed' && (
        <div className="card" style={{ marginTop: 20, textAlign: 'center', padding: 40 }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>✅</div>
          <h3>Scan Complete!</h3>
          <p style={{ color: 'var(--text-muted)', marginBottom: 20 }}>
            Redirecting to results...
          </p>
          <button className="btn btn-primary" onClick={() => navigate(`/results/${scanId}`)}>
            View Results
          </button>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="card" style={{ marginTop: 20, borderColor: 'var(--severity-critical)' }}>
          <div style={{ color: 'var(--severity-critical)', fontWeight: 600, marginBottom: 8 }}>
            ⚠️ Error
          </div>
          <p style={{ color: 'var(--text-secondary)' }}>{error}</p>
          <button
            className="btn btn-secondary"
            onClick={() => { setError(''); setScanning(false); setScanId(null); setCurrentStage(''); }}
            style={{ marginTop: 12 }}
          >
            Try Again
          </button>
        </div>
      )}
    </div>
  );
}
