# Novelty: Program-Flow-Aware Secret Reconstruction and Exposure Analysis

## 1. Existing Approaches (Prior Art)

### 1.1 Pattern Matching / Regex Detection
Tools like **TruffleHog**, **git-secrets**, and **detect-secrets** use regular expressions to identify known secret formats (e.g., AWS keys matching `AKIA[A-Z0-9]{16}`). While effective for directly hardcoded credentials, they cannot detect secrets assembled from multiple fragments.

### 1.2 Entropy Analysis
Shannon entropy measures the randomness of strings. High-entropy strings in source code may be secrets. However, entropy alone produces many false positives (e.g., UUIDs, hashes, encoded data) and cannot detect fragmented secrets.

### 1.3 Static Analysis (SAST)
Commercial SAST tools (SonarQube, Checkmarx, Fortify) perform broader code analysis but primarily focus on vulnerability patterns (SQL injection, XSS) rather than secret-specific reconstruction from fragments.

### 1.4 AI-Assisted Detection
Recent approaches use machine learning or LLMs to classify whether detected strings are real secrets. These provide better false positive filtering but still rely on the underlying detection mechanism to find candidates.

### 1.5 Limitations of Existing Approaches

| Approach | Direct Secrets | Fragmented Secrets | Propagation | Exposure |
|----------|:---:|:---:|:---:|:---:|
| Regex | ✅ | ❌ | ❌ | ❌ |
| Entropy | ⚠️ High FP | ❌ | ❌ | ❌ |
| SAST | ✅ | ⚠️ Limited | ⚠️ Generic | ⚠️ Generic |
| AI-Assisted | ✅ | ❌ | ❌ | ❌ |

## 2. Proposed Mechanism

### Program-Flow-Aware Secret Reconstruction and Exposure Analysis

The proposed mechanism addresses a gap in existing approaches: the detection of **secrets constructed from multiple source-code fragments**, followed by tracking their **propagation through program flow** to identify **exposure sinks**.

### 2.1 Fragment Detection
The system identifies string variable assignments and operations that may constitute parts of a credential:
- Direct string constants
- String concatenation operations
- String formatting (f-strings, .format())
- Base64 decoding of static values

### 2.2 Secret Reconstruction
Using **constant propagation** and **AST-based analysis** (for Python) or **regex-based parsing** (for other languages), the system assembles the complete secret value:

```
p1 = "AKIA"          → Fragment A
p2 = "TEST1234"      → Fragment B
p3 = "DEMO5678"      → Fragment C
key = p1 + p2 + p3   → Reconstructed: "AKIATEST1234DEMO5678"
```

The reconstruction explicitly reports its status:
- **FULL** — All fragments statically resolved
- **PARTIAL** — Some fragments contain dynamic/unresolvable values
- **UNRESOLVED** — Could not determine the final value

### 2.3 Program-Flow Propagation Tracking
After reconstruction, the system uses **taint analysis** to track how the secret value flows through the program:

```
key (origin)
  ↓ assignment
auth = key
  ↓ dict insertion
headers["Authorization"] = auth
  ↓ function argument
requests.get(url, headers=headers)
```

This is represented as a **directed propagation graph** with nodes (variables) and edges (data flow).

### 2.4 Exposure Sink Identification
The propagation graph's terminal nodes are analyzed to identify **exposure sinks** — points where the secret reaches a potentially dangerous output:

| Sink Type | Risk | Examples |
|-----------|------|----------|
| Network Request | HIGH | `requests.get()`, `fetch()`, `axios.post()` |
| Auth Header | HIGH | `headers["Authorization"]` |
| Log Output | LOW | `print()`, `console.log()` |
| File Write | MEDIUM | `open()`, `fs.writeFile()` |
| Database | MEDIUM | `cursor.execute()`, `db.insert()` |

### 2.5 Combined Pipeline

```
Fragment Detection
       ↓
Secret Reconstruction (constant propagation)
       ↓
Program-Flow Propagation (taint tracking)
       ↓
Exposure Sink Identification (risk classification)
       ↓
Transparent Risk Scoring
```

## 3. Contribution

Based on the project's prior-art investigation, the proposed mechanism — specifically the combination of **fragmented secret reconstruction** with **program-flow propagation tracking** and **exposure sink identification** — was not found as a directly matching approach in the searched patent results and existing open-source tools.

While individual components (static analysis, taint tracking, secret detection) exist independently, their specific combination for the purpose of **reconstructing fragmented credentials and tracing them to exposure points** represents the project's central contribution.

## 4. Evaluation Methodology

The contribution is demonstrated by comparing:

**Baseline:** Regex + Entropy detection only
**Proposed:** Regex + Entropy + Reconstruction + Dataflow + Sink Analysis

Key metrics:
- Fragmented secrets detected (0 by baseline, >0 by proposed)
- Propagation paths identified
- Exposure sinks classified
- False positive rate
- Risk score accuracy

## 5. Limitations

This is an academic prototype, not a commercial SAST tool:
- Single-file analysis scope
- No cross-file dataflow
- No runtime/dynamic analysis
- Limited to statically resolvable values
- Reports limitations explicitly (PARTIAL/UNRESOLVED status)
