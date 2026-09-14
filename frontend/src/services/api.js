/**
 * API Service — Centralized HTTP client for the backend
 */

import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 300000, // 5 min for scans
});

// ─── Scan Endpoints ──────────────────────────────────────────────────────

export async function uploadAndScan(file, repositoryName) {
  const formData = new FormData();
  formData.append('repository', file);
  formData.append('repositoryName', repositoryName || file.name.replace('.zip', ''));

  const response = await api.post('/scans', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
}

export async function listScans() {
  const response = await api.get('/scans');
  return response.data;
}

export async function getScan(scanId) {
  const response = await api.get(`/scans/${scanId}`);
  return response.data;
}

export async function getScanFindings(scanId) {
  const response = await api.get(`/scans/${scanId}/findings`);
  return response.data;
}

// ─── Finding Endpoints ───────────────────────────────────────────────────

export async function getFinding(findingId) {
  const response = await api.get(`/findings/${findingId}`);
  return response.data;
}

export async function requestAIAnalysis(findingId) {
  const response = await api.post(`/findings/${findingId}/ai-analysis`);
  return response.data;
}

// ─── Report Endpoints ────────────────────────────────────────────────────

export function getReportUrl(scanId) {
  return `${API_BASE}/reports/${scanId}`;
}

// ─── Health ──────────────────────────────────────────────────────────────

export async function checkHealth() {
  const response = await api.get('/health');
  return response.data;
}

export default api;
