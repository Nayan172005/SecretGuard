# SecretGuard

Program-Flow-Aware Source Code Secret Detection with Fragmented Secret Reconstruction and Exposure Analysis.

SecretGuard is a static application security testing (SAST) system that detects hardcoded secrets in source-code repositories. Beyond standard literal matching, it identifies credentials assembled from multiple source fragments, traces their intra-procedural propagation via taint analysis, classifies operational exposure sinks, and calculates an explainable multi-component risk score.

---

## Problem Overview

Standard secret scanners rely on static regular expressions and Shannon entropy heuristics. While effective for monolithic literal tokens, they fail when credentials are split across multiple programmatic statements or variable assignments:

```python
part1 = "AKIA"
part2 = "TESTFRAG"
part3 = "MENT12345678"

# Invisible to literal pattern matching; individual fragments lack secret format and entropy
access_key = part1 + part2 + part3

# Uncontextualized scanners do not track whether the secret reaches an external sink
headers = {"Authorization": access_key}
requests.get("https://api.cloud.com/data", headers=headers)
```

SecretGuard addresses two core gaps:
1. **Fragmented Assembly:** Statically reconstructing secrets assembled across variables, concatenations, string formatting (f-strings), list joins, and static Base64 decoding.
2. **Exposure Context:** Tracing dataflow propagation to determine whether a secret terminates locally or reaches an outbound operational sink (network request, authorization header, database write, or log stream).

---

## System Architecture

The platform is organized into three decoupled computing tiers and a post-detection advisory service.

![SecretGuard Architecture](docs/fig1_architecture.png)

* **Client Tier (React 18 + Vite):** Interactive dashboard providing real-time scan progress, finding matrices, AST propagation graphs, risk score breakdowns, and PDF report downloads.
* **Orchestration Gateway (Node.js + Express):** Ingestion controller with Zip-Slip path-traversal guards, REST API dispatch, and task coordination.
* **Analysis Engine (Python 3 + FastAPI):** Autonomous 8-stage static analysis engine executing deterministic AST parsing, taint tracking, and risk calculation.
* **Advisory Layer (Google Gemini API):** Downstream generative service that receives sanitized, masked finding summaries to generate contextual remediation recommendations without exposing raw repository code.

---

## Detection and Analysis Pipeline

The detection engine executes an 8-stage sequential pipeline. Candidate extraction is local and deterministic.

![Detection Pipeline](docs/fig3_detection_pipeline.png)

1. **File Scanner:** Recursively discovers files across 25+ language extensions. Filters binary files (null-byte inspection), minified files (line length > 500 characters), files exceeding 1 MB, and vendor directories (`node_modules`, `.git`, `venv`, `dist`).
2. **Regex Detector:** Pattern-matching engine with 20+ specialized credential expressions (AWS, Google Cloud, GitHub, Slack, Stripe, SendGrid, Twilio, JWTs, private keys, database URIs).
3. **Entropy Analyzer:** Evaluates character randomness using Shannon entropy with type-aware adaptive thresholds (Hexadecimal > 3.0, Base64 > 4.0, General ASCII > 4.5).
4. **Context Filter:** Suppresses false positives using a dummy placeholder blacklist (`your_api_key_here`, `xxxxxx`), test-suite markers, comment/docstring detectors, and character repetition checks.
5. **Secret Reconstructor:** Parses Python AST (and applies grammar-based parsing for JavaScript/TypeScript) to build an intra-procedural constant symbol table. Resolves binary additions (`+`), f-strings, `.format()` expressions, list joins, and static `base64.b64decode()` calls. Emits explicit reconstruction statuses (`FULL`, `PARTIAL`, `UNRESOLVED`).
6. **Pre-Finding Validator:** Enforces length (>= 12 characters) and Shannon entropy (>= 3.2) filters to discard benign string concatenations. Recognizes system configuration retrieval APIs (`os.environ.get`, `os.getenv`, `process.env`) as externalized configuration and excludes them from hardcoded-secret alerts.
7. **Dataflow Tracker:** Performs intra-procedural taint analysis across variable assignments, collection/dictionary subscript insertions (`headers['Authorization'] = key`), and function arguments, outputting a directed acyclic propagation graph (DAG).
8. **Sink Analyzer & Risk Engine:** Maps terminal graph nodes to a prioritized exposure sink taxonomy and calculates an explainable composite risk score.

![Reconstruction and Exposure Workflow](docs/fig2_reconstruction_workflow.png)

---

## Risk Scoring Model

Each finding is evaluated using a continuous, transparent 0–100 score composed of four orthogonal 25-point sub-scores:

```
Risk Score (0-100) = Detection Confidence (0-25)
                   + Secret Sensitivity (0-25)
                   + Exposure Severity (0-25)
                   + Propagation Certainty (0-25)
```

| Component | Range | Scoring Logic |
| :--- | :--- | :--- |
| **Detection Confidence** | 0–25 | Scaled from pattern confidence; +3 to +5 bonus for multi-method detection; +2 bonus for high Shannon entropy (> 4.5). |
| **Secret Sensitivity** | 0–25 | Calibrated by credential type: AWS Secret / Stripe / Private Key = 25; AWS Access Key = 24; Database URI / GitHub PAT = 23; Google Key / JWT = 22; Generic = 15; UUID = 8. |
| **Exposure Severity** | 0–25 | Calibrated by sink hazard: Network Request = 25; Auth Header = 24; API Call = 23; Database = 15; File Write = 14; Config = 12; Log = 10; Unexposed = 3. |
| **Propagation Certainty** | 0–25 | Base score = 5; +10 bonus for `FULL` reconstruction; +5 bonus for `PARTIAL` reconstruction; path length bonus = `min(10, path_length * 2)`. |

### Severity Thresholds

* **Critical:** 80 – 100
* **High:** 60 – 79
* **Medium:** 30 – 59
* **Low:** 0 – 29

---

## Experimental Results

The engine was evaluated through automated test suites and three benchmark repository archetypes.

![SecretGuard Dashboard](docs/fig4_frontend_dashboard.png)

### Automated Test Suite Coverage

The automated test suite (`tests/test_engine.py`) consists of 37 unit and integration test cases across all engine modules, executing with a 100% pass rate:

| Module Under Test | Test Cases | Passed | Pass Rate | Test Focus |
| :--- | :---: | :---: | :---: | :--- |
| Regex Pattern Detector | 5 | 5 | 100% | Pattern detection across AWS, Google, GitHub, JWT, DB URIs |
| Entropy Analyzer | 3 | 3 | 100% | Shannon entropy across Hex, Base64, and ASCII sequences |
| Context Filter | 2 | 2 | 100% | Placeholder suppression and test fixture detection |
| Secret Reconstructor | 6 | 6 | 100% | Multi-part concat, f-strings, JS concat, status reporting |
| Dataflow Tracker | 3 | 3 | 100% | Variable assignment, dictionary insertion, call argument tracking |
| Exposure Sink Analyzer | 6 | 6 | 100% | Network requests, auth headers, logging sinks, multi-sink priority |
| Risk Scoring Engine | 3 | 3 | 100% | Boundary validation, component summation, severity thresholds |
| Defensive Masking & Dedup | 2 | 2 | 100% | Deterministic secret masking and duplicate finding consolidation |
| End-to-End Pipeline & Ablation | 7 | 7 | 100% | Fragmented discovery, baseline comparison, safe filtering |
| **Total Test Suite** | **37** | **37** | **100%** | Deterministic pipeline validation |

### Benchmark Repository Evaluation

| Repository Archetype | Files | Lines | Candidates | Confirmed Findings | Reconstructed Secrets | Average Risk | Severity Distribution |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Safe Repository** (`clean_code.py`) | 1 | 50 | 0 | 0 | 0 | 0.0 (Clean) | 0 Critical, 0 High, 0 Medium, 0 Low |
| **Vulnerable Repository** (`hardcoded_secrets.py`) | 1 | 35 | 17 | 8 | 0 | 52.4 (Medium) | 2 Critical, 0 High, 6 Medium, 0 Low |
| **Fragmented Repository** (`example.py`, `api_client.js`) | 2 | 102 | 14 | 10 | 5 | 68.6 (High) | 3 Critical, 3 High, 4 Medium, 0 Low |

### Internal Baseline vs. Proposed Approach

An ablation comparison was conducted against an internal literal-detection baseline (`Regex + Shannon Entropy only` via `/scan/baseline`):

| Capability / Metric | Internal Literal Baseline | SecretGuard (Full Pipeline) | Result |
| :--- | :--- | :--- | :--- |
| Contiguous Literal Secrets | Detected (all 8 found) | Detected (all 8 found) | Parity on monolithic literals |
| Fragmented Credentials | 0 detected | 5 reconstructed (`FULL`/`PARTIAL`) | Recovers split credentials |
| Benign Concat Suppression | Flags raw strings | Pre-validation suppresses benign operations | 0 false alarms on clean repo |
| Dataflow Tracking | Not supported | Directed propagation DAG | Full variable lineage traced |
| Exposure Sink Mapping | Not supported | Classified by priority hierarchy | Differentiates network vs. logs |
| Risk Scoring | Flat binary alert | Continuous 0–100 explainable score | Context-calibrated risk |

### Reconstructed Secret Inventory (Fragmented Benchmark)

| Target Variable | Source File | Fragments | Status | Masked Value | Exposure Sink | Risk Score |
| :--- | :--- | :---: | :---: | :--- | :--- | :---: |
| `access_key` | `example.py` | 3 | FULL | `AKIA****************5678` | Local assignment (None) | 64.0 (High) |
| `github_token` | `example.py` | 2 | FULL | `ghp_****************cdef` | Network Request (`requests.get`) | 89.0 (Critical) |
| `connection_string` | `example.py` | 5 | FULL | `mong****************tion` | Local assignment (None) | 63.0 (High) |
| `mixed_key` | `example.py` | 2 | PARTIAL | `pref********************` | Dynamic retrieval (None) | 39.0 (Medium) |
| `apiKey` | `api_client.js` | 2 | FULL | `AIza****************6789` | Network Request (`axios.post`) | 86.0 (Critical) |

---

## Project Structure

```
SecretGuard/
├── frontend/                     # React 18 + Vite dashboard
│   ├── src/
│   │   ├── components/           # Navigation, charts, propagation graphs
│   │   ├── pages/                # Dashboard, Scan, Results, Findings, Reports
│   │   └── services/             # Axios API client
│   └── package.json
├── backend/                      # Node.js + Express API server
│   ├── src/
│   │   ├── controllers/          # Scan, finding, report controllers
│   │   ├── routes/               # Express REST routes
│   │   ├── services/             # Ingestion, MongoDB, PDFKit, Gemini service
│   │   └── server.js
│   └── package.json
├── detection-engine/             # Python 3 static analysis engine
│   ├── scanner/
│   │   ├── file_scanner.py       # Recursive file discovery and filtering
│   │   ├── regex_detector.py     # 20+ credential pattern rules
│   │   ├── entropy_analyzer.py   # Type-aware Shannon entropy analyzer
│   │   ├── context_filter.py     # False-positive suppressor
│   │   ├── secret_reconstructor.py # AST-based symbol table and fragment resolver
│   │   ├── secret_validator.py   # Pre-finding statistical and env-var validator
│   │   ├── dataflow_tracker.py   # Intra-procedural taint propagation tracker
│   │   ├── sink_analyzer.py      # Prioritized exposure sink classifier
│   │   ├── risk_engine.py        # 4-component continuous risk scoring
│   │   ├── deduplicator.py       # Finding consolidation
│   │   └── models.py             # Data models and structures
│   ├── tests/
│   │   └── test_engine.py        # Automated test suite (37 tests)
│   ├── main.py                   # FastAPI service
│   └── requirements.txt
├── sample-repositories/          # Synthetic benchmark datasets
│   ├── clean_code/               # Compliant repository archetype
│   ├── hardcoded_secrets/        # Monolithic credential repository archetype
│   └── fragmented_secret/        # Multi-fragment credential repository archetype
├── docs/                         # System diagrams and technical specifications
│   ├── fig1_architecture.png
│   ├── fig2_reconstruction_workflow.png
│   ├── fig3_detection_pipeline.png
│   └── fig4_frontend_dashboard.png
└── README.md
```

---

## Installation and Setup

### Prerequisites

* Python 3.10+
* Node.js 18+ LTS
* MongoDB (optional; falls back automatically to in-memory store)

### 1. Detection Engine Setup

```bash
cd detection-engine
python -m venv venv

# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
python main.py
```
The detection service starts at `http://localhost:8000`.

To run the automated test suite:
```bash
pytest tests/ -v
```

### 2. Backend Gateway Setup

```bash
cd backend
npm install

# Configure environment variables
cp .env.example .env
npm run dev
```
The gateway starts at `http://localhost:5000`.

### 3. Frontend Dashboard Setup

```bash
cd frontend
npm install
npm run dev
```
The client starts at `http://localhost:3000`.

---

## Environment Configuration

### Backend (`backend/.env`)

```ini
PORT=5000
MONGODB_URI=mongodb://localhost:27017/secretguard
PYTHON_ENGINE_URL=http://localhost:8000
GEMINI_API_KEY=your_gemini_api_key_here # Optional: advisory recommendations
MAX_UPLOAD_SIZE_MB=100
```

### Frontend (`frontend/.env`)

```ini
VITE_API_URL=http://localhost:5000/api
```

---

## REST API Reference

### Backend Gateway Endpoints (`http://localhost:5000`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health status |
| `POST` | `/api/scans` | Upload repository archive (ZIP) and initiate scan |
| `GET` | `/api/scans` | List all past scan executions |
| `GET` | `/api/scans/:id` | Fetch scan summary and status |
| `GET` | `/api/scans/:id/findings` | Fetch all findings for a scan with filter support |
| `GET` | `/api/findings/:id` | Fetch granular finding details, propagation path, and sink |
| `POST` | `/api/findings/:id/ai-analysis` | Request post-detection Gemini remediation advice |
| `GET` | `/api/reports/:scanId` | Generate and download formal PDF security report |

### Python Engine Endpoints (`http://localhost:8000`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Static analysis engine health check |
| `POST` | `/scan` | Execute complete 8-stage analysis pipeline on target path |
| `POST` | `/scan/baseline` | Execute literal baseline (Regex + Entropy only) for comparison |

---

## Defensive Security Invariants

* **Deterministic Secret Masking:** Detected tokens are masked immediately (`mask_secret()`) displaying only prefix and suffix characters (`AKIA****************5678`). Raw secret strings are never logged or persisted.
* **Advisory Isolation:** Complete secrets and source code files are never transmitted to external APIs. Only sanitized metadata (masked value, line number, sink type) is sent to Gemini.
* **Zip-Slip Protection:** Archive decompression routines validate entry targets against destination root paths, rejecting directory traversal payloads (`../`).
* **Non-Execution Invariant:** Source code is analyzed statically via syntax tree parsing. Uploaded code is never executed, compiled, or loaded into runtime interpreters.

---

## Current Scope and Limitations

* **Intra-Procedural Scope:** Taint tracking operates within single source files; cross-file imports and module-level dataflows are not currently resolved.
* **Control-Flow Sensitivity:** Static reconstruction resolves linear assignments and constant propagations; complex dynamic runtime conditions (e.g., conditional loops, polymorphic dynamic dispatch) are reported as `PARTIAL` or `UNRESOLVED`.
* **Language Support:** Native AST-level constant propagation is implemented for Python, with grammar-based regex state tracking for JavaScript/TypeScript. Compiled languages currently use lexical pattern analysis.

---

## License

Copyright (c) 2026 Nayan Sharma. All rights reserved.

This repository is published for educational, research, and demonstration
purposes. The source code and associated materials are proprietary.

Viewing and forking this repository through GitHub are permitted for
inspection and study. No permission is granted to copy, modify, redistribute,
republish, sublicense, commercially exploit, or create derivative works from
the source code without prior written permission from the author.

Attribution alone does not constitute permission to reuse the source code.

For permissions or collaboration inquiries, please contact:
nayan.sharma172005@gmail.com