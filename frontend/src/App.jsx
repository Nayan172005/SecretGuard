/**
 * App.jsx — Main application with React Router
 * SecretGuard — AI-Based Source Code Secret Detector
 */

import React from 'react';
import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanResults from './pages/ScanResults';
import FindingDetail from './pages/FindingDetail';
import ScanHistory from './pages/ScanHistory';

function App() {
  return (
    <Router>
      <div className="app-layout">
        {/* Sidebar */}
        <nav className="sidebar">
          <div className="sidebar-brand">
            <div className="brand-icon">🛡️</div>
            <div>
              <h1>SecretGuard</h1>
              <div className="brand-subtitle">Source Code Scanner</div>
            </div>
          </div>

          <div className="sidebar-nav">
            <NavLink to="/" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`} end>
              <span className="nav-icon">📊</span>
              Dashboard
            </NavLink>
            <NavLink to="/scan" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
              <span className="nav-icon">🔍</span>
              New Scan
            </NavLink>
            <NavLink to="/history" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
              <span className="nav-icon">📋</span>
              Scan History
            </NavLink>
          </div>

          <div style={{ padding: '16px', borderTop: '1px solid var(--border-default)' }}>
            <div style={{ fontSize: '10px', color: 'var(--text-muted)', textAlign: 'center' }}>
              Program-Flow-Aware<br />
              Secret Reconstruction<br />
              & Exposure Analysis
            </div>
          </div>
        </nav>

        {/* Main Content */}
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan" element={<NewScan />} />
            <Route path="/results/:scanId" element={<ScanResults />} />
            <Route path="/finding/:findingId" element={<FindingDetail />} />
            <Route path="/history" element={<ScanHistory />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
