# Secret Detection Engine

Python-based detection engine implementing Program-Flow-Aware Secret Reconstruction and Exposure Analysis.

## Modules

| Module | Purpose |
|--------|---------|
| `file_scanner.py` | Recursive file discovery with language detection |
| `regex_detector.py` | 20+ regex patterns for common secret types |
| `entropy_analyzer.py` | Shannon entropy with context-aware boosting |
| `context_filter.py` | False positive reduction |
| `secret_reconstructor.py` | ⭐ Fragment detection + secret reconstruction |
| `dataflow_tracker.py` | ⭐ Program-flow propagation tracking |
| `sink_analyzer.py` | ⭐ Exposure sink identification |
| `risk_engine.py` | Transparent 4-component risk scoring |
| `models.py` | Data models for findings, graphs, sinks |

## Running

```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
python main.py
```

Server starts on `http://localhost:8000`

## Testing

```bash
python tests/test_engine.py
```

## API

- `GET /health` — Health check
- `POST /scan` — Run full analysis pipeline
- `POST /scan/baseline` — Run baseline (regex+entropy only) for comparison
