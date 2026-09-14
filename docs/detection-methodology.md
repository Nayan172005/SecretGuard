# Detection Methodology

## Overview

The detection engine implements an 8-stage pipeline that goes beyond traditional regex-based secret detection by incorporating **Program-Flow-Aware Secret Reconstruction and Exposure Analysis**.

## Stage 1: File Scanning

**Module:** `scanner/file_scanner.py`

Recursively discovers source code files, supporting 25+ file types across Python, JavaScript, TypeScript, Java, C/C++, Go, PHP, Ruby, JSON, YAML, and configuration files.

Filters:
- Binary files (null byte detection)
- Minified files (average line length > 500)
- Files > 1MB
- Vendor directories (node_modules, .git, venv, build, dist)

## Stage 2: Regex Detection

**Module:** `scanner/regex_detector.py`

20+ configurable patterns for common secret types:
- AWS Access Keys / Secret Keys
- Google API Keys
- GitHub Tokens (classic, fine-grained, OAuth)
- Slack Tokens / Webhooks
- JWTs
- Private Key headers
- Database connection strings
- Stripe, SendGrid, Twilio keys
- Generic API keys, passwords, bearer tokens

Each pattern has an associated confidence level (0.0-1.0).

## Stage 3: Entropy Analysis

**Module:** `scanner/entropy_analyzer.py`

Calculates Shannon entropy: H = -Σ p(x) · log₂(p(x))

Thresholds are string-type-aware:
- Hex strings: > 3.0
- Base64 strings: > 4.0
- General strings: > 4.5

Entropy is a **supporting signal**, not the sole detection mechanism. Confidence is boosted when high-entropy strings appear near credential-related keywords.

## Stage 4: Context Filtering

**Module:** `scanner/context_filter.py`

Reduces false positives by checking:
- Known placeholder values (`your_api_key_here`, `xxxxxxxx`, etc.)
- Documentation context (comments, docstrings)
- Test file detection
- Repetitive character patterns
- Configuration placeholder variable names

## Stage 5: Secret Reconstruction (CORE NOVELTY)

**Module:** `scanner/secret_reconstructor.py`

Detects and reconstructs secrets assembled from multiple code fragments.

**Algorithm:**
1. Parse source code into AST (Python) or use regex (other languages)
2. Build symbol table of constant string assignments
3. Identify concatenation, f-string, .format(), .join(), base64.b64decode operations
4. Resolve operands using the symbol table
5. Build reconstructed value with explicit status

**Reconstruction Status:**
- `FULL` — All fragments statically resolved
- `PARTIAL` — Some fragments dynamic/unresolvable
- `UNRESOLVED` — Could not determine value

## Stage 6: Dataflow Tracking (CORE NOVELTY)

**Module:** `scanner/dataflow_tracker.py`

Tracks how reconstructed secrets propagate through variable assignments.

**Approach:** Taint analysis
1. Mark secret-holding variables as "tainted"
2. Walk AST chronologically
3. Any variable assigned from a tainted variable becomes tainted
4. Track through assignments, dictionary insertions, function arguments

**Output:** Directed propagation graph (nodes = variables, edges = data flow)

## Stage 7: Sink Analysis (CORE NOVELTY)

**Module:** `scanner/sink_analyzer.py`

Examines propagation graph terminal nodes and code patterns to identify exposure sinks.

**Sink Categories:**
| Type | Risk | Functions |
|------|------|-----------|
| Network | HIGH | requests.get/post, fetch, axios, http.request |
| Auth | HIGH | Authorization headers, Bearer tokens |
| Database | MEDIUM | cursor.execute, db.insert, collection.save |
| File | MEDIUM | open, fs.writeFile |
| Logging | LOW | print, console.log, logger.* |

## Stage 8: Risk Scoring

**Module:** `scanner/risk_engine.py`

Transparent 4-component scoring:

| Component | Range | Factors |
|-----------|-------|---------|
| Detection Confidence | 0-25 | Number of methods, confidence score, entropy |
| Secret Sensitivity | 0-25 | Secret type (AWS=25, UUID=8, etc.) |
| Exposure Severity | 0-25 | Sink type (Network=25, Log=10, None=3) |
| Propagation Certainty | 0-25 | Reconstruction status, path length |

Every finding includes a detailed breakdown explaining **why** it received its score.
