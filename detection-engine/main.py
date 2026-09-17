"""
Main Detection Engine — FastAPI Server

This is the entry point for the Python detection engine.
It exposes HTTP endpoints for the Node.js backend to call and
orchestrates the complete analysis pipeline:

1. File scanning
2. Regex detection
3. Entropy analysis
4. Context filtering
5. Secret reconstruction (CORE NOVELTY)
6. Secret validation (post-reconstruction filtering)
7. Dataflow tracking (CORE NOVELTY)
8. Exposure sink analysis (CORE NOVELTY)
9. Risk scoring

The engine runs as a standalone HTTP service and communicates
with the Node.js backend via REST.
"""

import os
import sys
import json
import time
import logging
from typing import List, Dict, Optional, Set, Tuple

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scanner.file_scanner import scan_directory, get_scan_summary, ScannedFile
from scanner.regex_detector import detect_secrets_in_content
from scanner.entropy_analyzer import analyze_entropy
from scanner.context_filter import filter_candidates
from scanner.secret_reconstructor import SecretReconstructor
from scanner.dataflow_tracker import DataflowTracker
from scanner.sink_analyzer import analyze_propagation_sinks, analyze_code_for_sinks
from scanner.risk_engine import score_finding
from scanner.secret_validator import validate_reconstructed_secret, is_environment_variable_usage
from scanner.deduplicator import deduplicate_findings
from scanner.models import (
    Finding, ScanResult, DetectionCandidate,
    ReconstructionStatus, mask_secret,
    PropagationGraph, ExposureSink, ExposureType
)

# ─── Logging Setup ────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# ─── FastAPI App ───────────────────────────────────────────────────────────

app = FastAPI(
    title="Secret Detection Engine",
    description="Program-Flow-Aware Secret Reconstruction and Exposure Analysis",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Request/Response Models ──────────────────────────────────────────────

class ScanRequest(BaseModel):
    path: str
    repository_name: str = "Unknown Repository"
    scan_id: str = ""


class ScanResponse(BaseModel):
    success: bool
    data: dict
    error: str = ""


class HealthResponse(BaseModel):
    status: str
    engine: str
    version: str


# ─── API Endpoints ────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
def health_check():
    return HealthResponse(
        status="healthy",
        engine="Secret Detection Engine",
        version="1.0.0",
    )


@app.post("/scan", response_model=ScanResponse)
def run_scan(request: ScanRequest):
    """
    Run the complete analysis pipeline on a directory.
    This is the main endpoint called by the Node.js backend.
    """
    logger.info(f"Starting scan for: {request.path}")
    start_time = time.time()

    try:
        if not os.path.isdir(request.path):
            raise HTTPException(status_code=400, detail=f"Path not found: {request.path}")

        result = perform_scan(request.path, request.repository_name, request.scan_id)
        result.scan_duration = time.time() - start_time

        logger.info(
            f"Scan completed: {result.files_scanned} files, "
            f"{len(result.findings)} findings in {result.scan_duration:.2f}s"
        )

        return ScanResponse(success=True, data=result.to_dict())

    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        return ScanResponse(
            success=False,
            data={},
            error=str(e),
        )


@app.post("/scan/baseline", response_model=ScanResponse)
def run_baseline_scan(request: ScanRequest):
    """
    Run BASELINE scan (regex + entropy only, no reconstruction/flow analysis).
    Used for comparison to demonstrate the novelty contribution.
    """
    logger.info(f"Starting BASELINE scan for: {request.path}")
    start_time = time.time()

    try:
        if not os.path.isdir(request.path):
            raise HTTPException(status_code=400, detail=f"Path not found: {request.path}")

        result = perform_baseline_scan(request.path, request.repository_name, request.scan_id)
        result.scan_duration = time.time() - start_time

        return ScanResponse(success=True, data=result.to_dict())

    except Exception as e:
        logger.error(f"Baseline scan failed: {e}", exc_info=True)
        return ScanResponse(success=False, data={}, error=str(e))


# ─── Core Analysis Pipeline ──────────────────────────────────────────────

def perform_scan(
    directory: str,
    repo_name: str = "Unknown",
    scan_id: str = "",
) -> ScanResult:
    """
    Execute the complete analysis pipeline:
    1. File scanning
    2. Regex detection
    3. Entropy analysis
    4. Context filtering
    5. Secret reconstruction
    6. Secret validation (post-reconstruction)
    7. Dataflow tracking
    8. Sink analysis
    9. Risk scoring
    10. Finding deduplication
    """
    result = ScanResult(repository_name=repo_name)
    if scan_id:
        result.scan_id = scan_id

    # ── Step 1: Scan files ──────────────────────────────────────────
    logger.info("Phase 1: Scanning files...")
    files = scan_directory(directory)
    summary = get_scan_summary(files)
    result.total_files = summary["total_files"]
    result.total_lines = summary["total_lines"]
    result.files_scanned = summary["total_files"]

    if not files:
        logger.warning("No supported files found in directory")
        return result

    # ── Step 2 & 3: Detect candidates (regex + entropy) ─────────────
    logger.info("Phase 2: Running regex detection...")
    logger.info("Phase 3: Running entropy analysis...")
    all_candidates: List[DetectionCandidate] = []

    for f in files:
        try:
            # Regex detection
            regex_candidates = detect_secrets_in_content(f.content, f.relative_path)
            all_candidates.extend(regex_candidates)

            # Entropy analysis
            entropy_candidates = analyze_entropy(f.content, f.relative_path)
            all_candidates.extend(entropy_candidates)
        except Exception as e:
            logger.warning(f"Error analyzing {f.relative_path}: {e}")
            continue

    logger.info(f"Found {len(all_candidates)} raw candidates")

    # ── Step 4: Context filtering ───────────────────────────────────
    logger.info("Phase 4: Applying context filter...")
    filtered_candidates = filter_candidates(all_candidates)
    logger.info(f"After filtering: {len(filtered_candidates)} candidates")
    result.candidates_found = len(filtered_candidates)

    # ── Step 5: Secret reconstruction (CORE NOVELTY) ────────────────
    logger.info("Phase 5: Running secret reconstruction...")
    reconstructor = SecretReconstructor()
    all_reconstructed = []

    for f in files:
        try:
            reconstructed = reconstructor.analyze_generic(
                f.content, f.relative_path, f.language
            )
            all_reconstructed.extend(reconstructed)
        except Exception as e:
            logger.warning(f"Reconstruction error in {f.relative_path}: {e}")
            continue

    logger.info(f"Reconstructed {len(all_reconstructed)} candidates from fragments")

    # ── Step 6: Secret validation (post-reconstruction) ──────────────
    logger.info("Phase 6: Validating reconstructed candidates...")
    validated_reconstructed = []
    for recon in all_reconstructed:
        # Get code context for validation
        code_context = ""
        for f in files:
            if f.relative_path == recon["file"]:
                ctx_start = max(0, recon["line"] - 4)
                ctx_end = min(len(f.lines), recon["line"] + 3)
                code_context = '\n'.join(f.lines[ctx_start:ctx_end])
                break

        is_secret, confidence, secret_type, reason = validate_reconstructed_secret(
            recon["reconstructed_value"],
            recon["target"],
            code_context,
            len(recon["fragments"]),
        )

        if is_secret:
            recon["_validated_confidence"] = confidence
            recon["_validated_secret_type"] = secret_type
            recon["_validated_reason"] = reason
            validated_reconstructed.append(recon)
            logger.info(f"  ✓ Validated: {recon['target']} → {secret_type} (confidence={confidence:.2f})")
        else:
            logger.info(f"  ✗ Rejected: {recon['target']} → {reason}")

    result.secrets_reconstructed = len(validated_reconstructed)
    logger.info(f"After validation: {len(validated_reconstructed)} confirmed secret reconstructions")

    # ── Step 7: Dataflow tracking (CORE NOVELTY) ────────────────────
    logger.info("Phase 7: Tracking dataflow propagation...")
    tracker = DataflowTracker()
    all_propagation_graphs: Dict[str, PropagationGraph] = {}

    for f in files:
        # Build secret variables from ALL confirmed sources:
        # - Validated reconstructions
        # - Direct regex/entropy detections
        secret_vars: Dict[str, Tuple[str, int]] = {}

        # From validated reconstructions
        for recon in validated_reconstructed:
            if recon["file"] == f.relative_path:
                target = recon["target"]
                value = recon["reconstructed_value"]
                line = recon["line"]
                secret_vars[target] = (value, line)

        # From direct regex/entropy hits — allow confirmed secrets to enter dataflow
        for candidate in filtered_candidates:
            if candidate.file_path == f.relative_path and candidate.context_variable:
                # Skip environment variable sourced candidates
                if not is_environment_variable_usage(candidate.code_context):
                    secret_vars[candidate.context_variable] = (
                        candidate.value, candidate.line_number
                    )

        if secret_vars:
            try:
                graphs = tracker.track_generic(
                    f.content, f.relative_path, secret_vars, f.language
                )
                all_propagation_graphs.update({
                    f"{f.relative_path}:{k}": v for k, v in graphs.items()
                })
            except Exception as e:
                logger.warning(f"Dataflow tracking error in {f.relative_path}: {e}")

    # ── Step 8: Sink analysis (CORE NOVELTY) ─────────────────────────
    logger.info("Phase 8: Analyzing exposure sinks...")

    # ── Step 9: Build findings and score ─────────────────────────────
    logger.info("Phase 9: Building and scoring findings...")

    # We'll collect all findings and then deduplicate
    raw_findings: List[Finding] = []

    # ── Create findings from direct regex/entropy detections ────────
    for candidate in filtered_candidates:
        finding = Finding(
            secret_type=candidate.secret_type,
            file_path=candidate.file_path,
            line_number=candidate.line_number,
            code_context=candidate.code_context,
            masked_secret=mask_secret(candidate.value),
            raw_secret=candidate.value,
            detection_methods=[candidate.detection_method],
            confidence=candidate.confidence,
            entropy_score=candidate.entropy_score,
        )

        # Attach propagation graph if available
        graph_key = f"{candidate.file_path}:{candidate.context_variable}"
        if graph_key in all_propagation_graphs:
            graph = all_propagation_graphs[graph_key]
            finding.propagation_graph = graph
            finding.propagation_path = graph.get_path()

            # Analyze sinks from propagation
            sinks = analyze_propagation_sinks(graph, candidate.file_path)
            if sinks:
                finding.exposure_sink = _select_best_sink(sinks)
                finding.exposure_type = finding.exposure_sink.sink_type.value

        # Also do direct code sink analysis for this variable
        if candidate.context_variable:
            for f in files:
                if f.relative_path == candidate.file_path:
                    direct_sinks = analyze_code_for_sinks(
                        f.content, f.relative_path, {candidate.context_variable}
                    )
                    if direct_sinks and not finding.exposure_sink:
                        finding.exposure_sink = _select_best_sink(direct_sinks)
                        finding.exposure_type = finding.exposure_sink.sink_type.value
                    elif direct_sinks and finding.exposure_sink:
                        finding.exposure_sink = _select_best_sink(
                            direct_sinks + [finding.exposure_sink]
                        )
                        finding.exposure_type = finding.exposure_sink.sink_type.value
                    break

        raw_findings.append(finding)

    # ── Create findings from validated reconstructed secrets ────────
    for recon in validated_reconstructed:
        reconstructed_value = recon["reconstructed_value"]
        secret_type = recon.get("_validated_secret_type", "Reconstructed Secret")

        # Determine code context
        code_context = ""
        for f in files:
            if f.relative_path == recon["file"]:
                ctx_start = max(0, recon["line"] - 4)
                ctx_end = min(len(f.lines), recon["line"] + 3)
                code_context = '\n'.join(f.lines[ctx_start:ctx_end])
                break

        finding = Finding(
            secret_type=secret_type,
            file_path=recon["file"],
            line_number=recon["line"],
            code_context=code_context,
            masked_secret=mask_secret(reconstructed_value),
            raw_secret=reconstructed_value,
            detection_methods=["reconstruction", "dataflow"],
            confidence=recon.get("_validated_confidence", 0.5),
            reconstruction_status=recon["status"],
            fragments=recon["fragments"],
            reconstructed_value_masked=mask_secret(reconstructed_value),
        )

        # Add propagation graph
        graph_key = f"{recon['file']}:{recon['target']}"
        if graph_key in all_propagation_graphs:
            graph = all_propagation_graphs[graph_key]
            finding.propagation_graph = graph
            finding.propagation_path = graph.get_path()

            sinks = analyze_propagation_sinks(graph, recon["file"])
            if sinks:
                finding.exposure_sink = _select_best_sink(sinks)
                finding.exposure_type = finding.exposure_sink.sink_type.value

        # Also do direct code sink analysis
        for f in files:
            if f.relative_path == recon["file"]:
                direct_sinks = analyze_code_for_sinks(
                    f.content, f.relative_path, {recon["target"]}
                )
                if direct_sinks and not finding.exposure_sink:
                    finding.exposure_sink = _select_best_sink(direct_sinks)
                    finding.exposure_type = finding.exposure_sink.sink_type.value
                elif direct_sinks and finding.exposure_sink:
                    finding.exposure_sink = _select_best_sink(
                        direct_sinks + [finding.exposure_sink]
                    )
                    finding.exposure_type = finding.exposure_sink.sink_type.value
                break

        raw_findings.append(finding)

    # ── Step 10: Deduplicate findings ────────────────────────────────
    logger.info("Phase 10: Deduplicating findings...")
    findings = deduplicate_findings(raw_findings)
    logger.info(f"After deduplication: {len(findings)} unique findings (from {len(raw_findings)})")

    # Score all findings
    for i, finding in enumerate(findings):
        findings[i] = score_finding(finding)

    # Sort findings by risk score (highest first)
    findings.sort(key=lambda f: f.risk_score, reverse=True)

    # Update severity counts
    for finding in findings:
        severity = finding.severity.value
        if severity in result.severity_counts:
            result.severity_counts[severity] += 1

    result.findings = findings

    if findings:
        result.average_risk_score = sum(f.risk_score for f in findings) / len(findings)

    return result


def _select_best_sink(sinks: List[ExposureSink]) -> ExposureSink:
    """Pick the most security-relevant exposure when multiple sinks exist."""
    priority = {
        ExposureType.NETWORK_REQUEST: 5,
        ExposureType.AUTH_HEADER: 4,
        ExposureType.API_CALL: 4,
        ExposureType.DATABASE: 3,
        ExposureType.FILE_WRITE: 2,
        ExposureType.LOG_OUTPUT: 1,
        ExposureType.CONSOLE_OUTPUT: 1,
        ExposureType.CONFIG_PROPAGATION: 1,
        ExposureType.UNKNOWN: 0,
    }
    return max(sinks, key=lambda sink: priority.get(sink.sink_type, 0))


def _deduplicate_findings(raw_findings: List[Finding]) -> List[Finding]:
    """Compatibility wrapper for the scanner-level deduplication helper."""
    return deduplicate_findings(raw_findings)


def _get_finding_dedup_key(finding: Finding) -> str:
    """
    Generate a stable deduplication key for a finding.
    Secrets at the same location with the same value should merge.
    """
    # Use the raw secret's first 12 chars + file for identity
    secret_sig = finding.raw_secret[:12] if finding.raw_secret else finding.masked_secret[:12]
    return f"{finding.file_path}:{secret_sig}"


def perform_baseline_scan(
    directory: str,
    repo_name: str = "Unknown",
    scan_id: str = "",
) -> ScanResult:
    """
    Baseline scan using only regex + entropy detection.
    No reconstruction, no dataflow tracking, no sink analysis.
    Used for comparison to demonstrate novelty contribution.
    """
    result = ScanResult(repository_name=repo_name)
    if scan_id:
        result.scan_id = scan_id

    files = scan_directory(directory)
    summary = get_scan_summary(files)
    result.total_files = summary["total_files"]
    result.total_lines = summary["total_lines"]
    result.files_scanned = summary["total_files"]

    all_candidates: List[DetectionCandidate] = []
    for f in files:
        try:
            regex_candidates = detect_secrets_in_content(f.content, f.relative_path)
            all_candidates.extend(regex_candidates)
            entropy_candidates = analyze_entropy(f.content, f.relative_path)
            all_candidates.extend(entropy_candidates)
        except Exception as e:
            continue

    filtered = filter_candidates(all_candidates)
    result.candidates_found = len(filtered)

    findings = []
    seen = set()
    for candidate in filtered:
        loc_key = f"{candidate.file_path}:{candidate.line_number}:{candidate.value[:10]}"
        if loc_key in seen:
            continue
        seen.add(loc_key)

        finding = Finding(
            secret_type=candidate.secret_type,
            file_path=candidate.file_path,
            line_number=candidate.line_number,
            code_context=candidate.code_context,
            masked_secret=mask_secret(candidate.value),
            raw_secret=candidate.value,
            detection_methods=[candidate.detection_method],
            confidence=candidate.confidence,
            entropy_score=candidate.entropy_score,
        )
        finding = score_finding(finding)
        findings.append(finding)

    findings.sort(key=lambda f: f.risk_score, reverse=True)
    for finding in findings:
        severity = finding.severity.value
        if severity in result.severity_counts:
            result.severity_counts[severity] += 1

    result.findings = findings
    if findings:
        result.average_risk_score = sum(f.risk_score for f in findings) / len(findings)

    return result


def _classify_reconstructed_secret(value: str) -> str:
    """Classify a reconstructed secret value by its pattern."""
    import re

    if re.match(r'^AKIA[A-Z0-9]{16}', value):
        return "AWS Access Key"
    if re.match(r'^AIza[0-9A-Za-z\-_]{20,}', value):
        return "Google API Key"
    if re.match(r'^ghp_[0-9a-zA-Z]{36}', value):
        return "GitHub Personal Access Token"
    if re.match(r'^sk_live_', value):
        return "Stripe Secret Key"
    if re.match(r'^Bearer\s+', value):
        return "Bearer Token"
    if 'mongodb' in value.lower() or 'postgres' in value.lower():
        return "Database Connection String"
    if len(value) >= 20:
        return "API Key"
    return "Reconstructed Secret"


# ─── Start Server ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("DETECTION_ENGINE_PORT", "8000"))
    logger.info(f"Starting detection engine on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
