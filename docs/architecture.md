# Architecture

## System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     React Frontend (Vite)                     │
│                                                               │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
│  │Dashboard │ │ New Scan │ │ Results  │ │ Finding Details  │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘ │
│  ┌──────────┐ ┌──────────┐                                    │
│  │ History  │ │ Reports  │                                    │
│  └──────────┘ └──────────┘                                    │
└──────────────────────┬────────────────────────────────────────┘
                       │ HTTP/REST (axios)
┌──────────────────────▼────────────────────────────────────────┐
│                 Node.js + Express Backend                      │
│                                                               │
│  ┌────────────┐ ┌────────────┐ ┌─────────────┐               │
│  │ Scan       │ │ Finding    │ │ Report      │               │
│  │ Controller │ │ Controller │ │ Controller  │               │
│  └──────┬─────┘ └──────┬─────┘ └──────┬──────┘               │
│         │              │              │                       │
│  ┌──────▼──────────────▼──────────────▼──────┐               │
│  │           Service Layer                    │               │
│  │  ┌──────────┐ ┌──────────┐ ┌────────────┐ │               │
│  │  │ Database │ │ Gemini   │ │   PDF      │ │               │
│  │  │ Service  │ │ Service  │ │ Generator  │ │               │
│  │  └──────────┘ └──────────┘ └────────────┘ │               │
│  └───────────────────────────────────────────┘               │
│         │                     │                               │
│    ┌────▼────┐           ┌────▼────┐                          │
│    │ MongoDB │           │ Gemini  │                          │
│    │(optional)│           │ API     │                          │
│    └─────────┘           └─────────┘                          │
└──────────────────────┬────────────────────────────────────────┘
                       │ Internal HTTP (axios)
┌──────────────────────▼────────────────────────────────────────┐
│              Python Detection Engine (FastAPI)                 │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                   Analysis Pipeline                      │  │
│  │                                                          │  │
│  │  Step 1: File Scanner                                    │  │
│  │     ↓                                                    │  │
│  │  Step 2: Regex Detector                                  │  │
│  │     ↓                                                    │  │
│  │  Step 3: Entropy Analyzer                                │  │
│  │     ↓                                                    │  │
│  │  Step 4: Context Filter                                  │  │
│  │     ↓                                                    │  │
│  │  Step 5: Secret Reconstructor  ← CORE NOVELTY           │  │
│  │     ↓                                                    │  │
│  │  Step 6: Dataflow Tracker      ← CORE NOVELTY           │  │
│  │     ↓                                                    │  │
│  │  Step 7: Sink Analyzer         ← CORE NOVELTY           │  │
│  │     ↓                                                    │  │
│  │  Step 8: Risk Engine                                     │  │
│  │                                                          │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

## Data Flow

1. User uploads ZIP → Frontend
2. Frontend sends multipart POST → Backend
3. Backend extracts ZIP safely (path traversal protection)
4. Backend calls Python engine via HTTP POST
5. Python engine runs 8-stage pipeline
6. Results returned to Backend
7. Backend stores in MongoDB (or in-memory)
8. Backend optionally calls Gemini for AI analysis
9. Frontend polls for status and displays results
10. User can download PDF report

## Risk Scoring Model

```
Risk Score (0-100) = Detection Confidence (0-25)
                   + Secret Sensitivity (0-25)
                   + Exposure Severity (0-25)
                   + Propagation Certainty (0-25)

Severity Classification:
  0-29  → LOW
  30-59 → MEDIUM
  60-79 → HIGH
  80-100 → CRITICAL
```
