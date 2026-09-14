# API Documentation

## Base URL
```
http://localhost:5000/api
```

## Endpoints

### Health Check
```
GET /api/health
```
**Response:**
```json
{
  "status": "healthy",
  "services": {
    "backend": "running",
    "database": "connected | in-memory mode",
    "pythonEngine": "healthy | unavailable",
    "gemini": "configured | not configured"
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

---

### Create Scan (Upload Repository)
```
POST /api/scans
Content-Type: multipart/form-data
```

**Parameters:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| repository | File (ZIP) | Yes | Source code repository |
| repositoryName | String | No | Display name |

**Response (201):**
```json
{
  "scanId": "uuid-string",
  "status": "scanning",
  "message": "Scan started"
}
```

---

### List Scans
```
GET /api/scans
```

**Response:**
```json
[
  {
    "scanId": "uuid",
    "repositoryName": "my-project",
    "status": "completed",
    "filesScanned": 42,
    "findingsCount": 5,
    "riskScore": 65.3,
    "severityCounts": { "CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1 },
    "createdAt": "2024-01-01T00:00:00.000Z"
  }
]
```

---

### Get Scan Details
```
GET /api/scans/:id
```

---

### Get Scan Findings
```
GET /api/scans/:id/findings
```

**Response:** Array of Finding objects sorted by risk score (descending).

---

### Get Finding Details
```
GET /api/findings/:id
```

**Response:**
```json
{
  "findingId": "abc12345",
  "secretType": "AWS Access Key",
  "filePath": "example.py",
  "lineNumber": 10,
  "maskedSecret": "AKIA**********5678",
  "detectionMethods": ["reconstruction", "dataflow"],
  "confidence": 0.85,
  "entropyScore": 4.123,
  "reconstructionStatus": "FULL",
  "fragments": [...],
  "propagationPath": ["part1", "key", "headers.Authorization", "requests.get()"],
  "propagationGraph": { "nodes": [...], "edges": [...] },
  "exposureSink": {
    "type": "External Network Request",
    "risk_level": "HIGH",
    "function": "requests.get"
  },
  "riskScore": 85.3,
  "severity": "CRITICAL",
  "riskBreakdown": {
    "detection_confidence": 22.5,
    "secret_sensitivity": 24.0,
    "exposure_severity": 25.0,
    "propagation_certainty": 13.8
  }
}
```

---

### Generate AI Analysis
```
POST /api/findings/:id/ai-analysis
```

**Response:**
```json
{
  "findingId": "abc12345",
  "aiAnalysisStatus": "completed",
  "explanation": "...",
  "impact": "...",
  "remediation": "...",
  "confidenceAssessment": "...",
  "executiveSummary": "..."
}
```

---

### Download PDF Report
```
GET /api/reports/:scanId
```

**Response:** PDF file download

---

## Error Responses

```json
{
  "error": "Description of the error"
}
```

| Status | Meaning |
|--------|---------|
| 400 | Invalid request (bad ZIP, wrong file type) |
| 404 | Resource not found |
| 413 | File too large |
| 429 | Rate limited |
| 500 | Internal server error |
