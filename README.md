# AI-Based Source Code Secret Detector

## Program-Flow-Aware Secret Reconstruction and Exposure Analysis

A web-based security scanner that analyzes uploaded source-code repositories to detect hardcoded secrets and credentials, with a novel mechanism for detecting **fragmented secrets** constructed from multiple code fragments.

---

## 🎯 Problem Statement

Existing secret detection tools primarily rely on regex pattern matching and entropy analysis. While effective for directly hardcoded secrets like `API_KEY = "AIza..."`, they fail to detect secrets that are **constructed from multiple fragments** in the source code:

```python
part1 = "AKIA"
part2 = "TEST1234"
part3 = "DEMO5678"
access_key = part1 + part2 + part3  # Invisible to traditional scanners
headers = {"Authorization": access_key}
requests.get("https://api.example.com", headers=headers)
```

## 🔬 Novelty: Program-Flow-Aware Secret Reconstruction

This project's **primary novelty** is:

**Program-Flow-Aware Secret Reconstruction and Exposure Analysis**

The system goes beyond traditional pattern matching by:

1. **Fragment Detection** — Identifying string fragments that may constitute parts of a secret
2. **Secret Reconstruction** — Statically assembling the complete secret from fragments via constant propagation and string concatenation analysis
3. **Program-Flow Propagation** — Tracking how the reconstructed secret flows through variables using taint analysis
4. **Exposure Sink Identification** — Determining where the secret eventually reaches (HTTP requests, auth headers, logging, etc.)

This mechanism detects secrets that are **invisible to baseline regex + entropy approaches**.

---

## 🏗️ Architecture

```
                    ┌──────────────────────┐
                    │     React Frontend   │
                    │ (Vite + Recharts)    │
                    └──────────┬───────────┘
                               │ REST API
                    ┌──────────▼───────────┐
                    │ Node.js + Express    │
                    │ Backend              │
                    └──────────┬───────────┘
                               │ Internal HTTP
                    ┌──────────▼───────────┐
                    │ Python Detection     │
                    │ Engine (FastAPI)     │
                    └──────────┬───────────┘
                               │ Verified findings
                    ┌──────────▼───────────┐
                    │ Gemini AI (optional) │
                    └──────────────────────┘
```

## 📁 Project Structure

```
project-root/
├── frontend/          # React + Vite dashboard
├── backend/           # Node.js + Express API server
├── detection-engine/  # Python detection engine
│   ├── scanner/
│   │   ├── file_scanner.py         # Recursive file discovery
│   │   ├── regex_detector.py       # Pattern-based detection
│   │   ├── entropy_analyzer.py     # Shannon entropy analysis
│   │   ├── context_filter.py       # False positive reduction
│   │   ├── secret_reconstructor.py # ⭐ Core novelty: fragment reconstruction
│   │   ├── dataflow_tracker.py     # ⭐ Core novelty: propagation tracking
│   │   ├── sink_analyzer.py        # ⭐ Core novelty: exposure identification
│   │   ├── risk_engine.py          # Transparent risk scoring
│   │   └── models.py              # Data models
│   ├── main.py                    # FastAPI server
│   └── tests/                     # Test suite
├── sample-repositories/           # Synthetic test data
├── reports/                       # Generated PDF reports
└── docs/                          # Documentation
```

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Node.js 18+
- MongoDB (optional — falls back to in-memory storage)

### 1. Detection Engine (Python)
```bash
cd detection-engine
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
python main.py
# Runs on http://localhost:8000
```

### 2. Backend (Node.js)
```bash
cd backend
cp .env.example .env
# Edit .env with your GEMINI_API_KEY (optional)
npm install
npm run dev
# Runs on http://localhost:5000
```

### 3. Frontend (React)
```bash
cd frontend
npm install
npm run dev
# Runs on http://localhost:3000
```

### 4. Open Dashboard
Navigate to **http://localhost:3000**

---

## 🔑 Environment Variables

### Backend (.env)
```
PORT=5000
MONGODB_URI=mongodb://localhost:27017/secret-detector
GEMINI_API_KEY=           # Optional — AI analysis unavailable without this
PYTHON_ENGINE_URL=http://localhost:8000
MAX_UPLOAD_SIZE_MB=100
```

### Frontend (.env)
```
VITE_API_URL=http://localhost:5000/api
```

**Important:** Never commit actual API keys. The system works without Gemini.

---

## 🎮 Demo Walkthrough

1. Open the dashboard at http://localhost:3000
2. Click **New Scan**
3. Upload the `sample-repositories/fragmented-secret/` as a ZIP
4. Watch scan progress through 10 stages
5. View findings with reconstruction evidence
6. Click a finding to see the propagation path visualization
7. Generate AI analysis (if Gemini configured)
8. Download PDF report

---

## 📊 Detection Pipeline

| Stage | Module | Purpose |
|-------|--------|---------|
| 1 | File Scanner | Recursive file discovery with language detection |
| 2 | Regex Detector | Pattern matching for 20+ secret types |
| 3 | Entropy Analyzer | Shannon entropy with context boosting |
| 4 | Context Filter | False positive reduction (placeholders, docs, tests) |
| 5 | **Secret Reconstructor** | ⭐ Fragment detection + constant propagation |
| 6 | **Dataflow Tracker** | ⭐ Taint-based propagation tracking |
| 7 | **Sink Analyzer** | ⭐ Exposure point identification + risk classification |
| 8 | Risk Engine | Transparent 4-component scoring (0-100) |
| 9 | Gemini AI | Explanation, impact, remediation (optional) |

---

## 📈 Evaluation: Baseline vs Proposed

| Metric | Baseline (Regex+Entropy) | Proposed (Full Pipeline) |
|--------|--------------------------|--------------------------|
| Fragmented secrets detected | 0 | ✅ Detected |
| Secret reconstruction | ❌ Not supported | ✅ FULL/PARTIAL status |
| Propagation tracking | ❌ Not supported | ✅ Graph-based |
| Exposure sink identification | ❌ Not supported | ✅ Classified by risk |
| Direct secrets detected | ✅ | ✅ |

---

## 🔒 Security Practices

- API keys from environment variables only
- ZIP path traversal protection
- File size limits
- No uploaded code execution
- Secrets masked in UI (e.g., `AKIA**********5678`)
- Minimal data sent to Gemini (masked findings only)
- CORS configuration
- Rate limiting
- Helmet security headers

---

## ⚠️ Limitations

- Single-file analysis (no cross-file tracking)
- Static analysis only (no runtime behavior)
- Python AST parsing for Python files; regex fallback for other languages
- Does not handle conditional assignments or complex control flow
- Reports PARTIAL status when reconstruction is incomplete
- Not a commercial-grade SAST tool

---

## 🔮 Future Work

- Cross-file dataflow tracking
- Support for more languages with AST parsers
- Inter-procedural analysis
- CI/CD integration
- Git history scanning
- Custom rule creation UI
- Enhanced visualizations

---

## 📝 API Documentation

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/scans` | POST | Upload ZIP and start scan |
| `/api/scans` | GET | List all scans |
| `/api/scans/:id` | GET | Get scan details |
| `/api/scans/:id/findings` | GET | Get findings for a scan |
| `/api/findings/:id` | GET | Get finding details |
| `/api/findings/:id/ai-analysis` | POST | Generate AI explanation |
| `/api/reports/:scanId` | GET | Download PDF report |

---

## 📚 Technology Stack

- **Frontend:** React 18, Vite, Recharts, Vanilla CSS
- **Backend:** Node.js, Express, Multer, PDFKit
- **Detection Engine:** Python 3, FastAPI, AST module
- **AI:** Google Gemini API (optional)
- **Database:** MongoDB with Mongoose (optional — in-memory fallback)

---

*Built as an academic cybersecurity project demonstrating Program-Flow-Aware Secret Reconstruction and Exposure Analysis.*
