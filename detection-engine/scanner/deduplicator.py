"""
Finding deduplication utilities.

Consolidates multiple detection methods that refer to the same underlying
secret without exposing raw values outside in-memory scanner state.
"""

from typing import Dict, List

from .models import Finding, ReconstructionStatus


def deduplicate_findings(raw_findings: List[Finding]) -> List[Finding]:
    """Merge findings that refer to the same secret in the same file."""
    dedup_map: Dict[str, Finding] = {}

    ordered_findings = sorted(
        raw_findings,
        key=lambda f: 0 if "reconstruction" in f.detection_methods else 1,
    )

    for finding in ordered_findings:
        key = get_finding_dedup_key(finding)
        related_key = _find_related_fragment_key(finding, dedup_map)
        if related_key:
            key = related_key

        if key not in dedup_map:
            dedup_map[key] = finding
            continue

        existing = dedup_map[key]

        for method in finding.detection_methods:
            if method not in existing.detection_methods:
                existing.detection_methods.append(method)

        existing.confidence = max(existing.confidence, finding.confidence)
        existing.entropy_score = max(existing.entropy_score, finding.entropy_score)

        if (
            finding.reconstruction_status != ReconstructionStatus.NONE
            and existing.reconstruction_status == ReconstructionStatus.NONE
        ):
            existing.reconstruction_status = finding.reconstruction_status
            existing.fragments = finding.fragments
            existing.reconstructed_value_masked = finding.reconstructed_value_masked

        if (
            finding.propagation_graph
            and (
                not existing.propagation_graph
                or len(finding.propagation_path) > len(existing.propagation_path)
            )
        ):
            existing.propagation_graph = finding.propagation_graph
            existing.propagation_path = finding.propagation_path

        if finding.exposure_sink and not existing.exposure_sink:
            existing.exposure_sink = finding.exposure_sink
            existing.exposure_type = finding.exposure_type
        elif (
            finding.exposure_sink
            and existing.exposure_sink
            and finding.exposure_sink.risk_level.value == "HIGH"
            and existing.exposure_sink.risk_level.value != "HIGH"
        ):
            existing.exposure_sink = finding.exposure_sink
            existing.exposure_type = finding.exposure_type

        generic_types = {"Generic Secret", "High Entropy String", "Reconstructed Secret"}
        if existing.secret_type in generic_types and finding.secret_type not in generic_types:
            existing.secret_type = finding.secret_type

        if len(finding.code_context) > len(existing.code_context):
            existing.code_context = finding.code_context

    return list(dedup_map.values())


def _find_related_fragment_key(
    finding: Finding,
    dedup_map: Dict[str, Finding],
) -> str:
    """
    Find an existing reconstructed finding that contains an entropy fragment.

    This reduces duplicate rows like "entropy fragment" plus "full
    reconstructed secret" while avoiding broad merging of unrelated direct
    credentials.
    """
    if finding.secret_type != "High Entropy String" or not finding.raw_secret:
        return ""

    for key, existing in dedup_map.items():
        if existing.file_path != finding.file_path or not existing.raw_secret:
            continue
        if "reconstruction" not in existing.detection_methods:
            continue
        if (
            len(finding.raw_secret) >= 8
            and finding.raw_secret in existing.raw_secret
            and finding.raw_secret != existing.raw_secret
        ):
            return key

    return ""


def get_finding_dedup_key(finding: Finding) -> str:
    """Generate a stable in-memory identity key for a finding."""
    if finding.raw_secret:
        return f"{finding.file_path}:raw:{finding.raw_secret[:12]}"
    variable_sig = finding.propagation_path[0] if finding.propagation_path else ""
    return f"{finding.file_path}:masked:{finding.masked_secret}:{variable_sig}"
