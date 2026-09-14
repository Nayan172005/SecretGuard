"""
Risk Scoring Engine
Provides transparent, explainable risk scoring for each finding.

The score is NOT a black box — each finding's score includes a breakdown
of contributing factors so users can understand WHY a particular
score was assigned.

Score components:
1. Detection Confidence (0-25): How reliably the secret was detected
2. Secret Sensitivity (0-25): How sensitive the secret type is
3. Exposure Severity (0-25): How dangerous the exposure sink is
4. Propagation Certainty (0-25): How certain we are about the flow

Total: 0-100
  0-29  → LOW
  30-59 → MEDIUM
  60-79 → HIGH
  80-100 → CRITICAL
"""

from typing import Dict, Optional
from .models import (
    Finding, RiskBreakdown, Severity,
    ReconstructionStatus, ExposureSink, SinkRisk, ExposureType
)


# ─── Configurable Weights ─────────────────────────────────────────────────

# Secret type sensitivity weights (0-25 scale)
SECRET_TYPE_WEIGHTS: Dict[str, float] = {
    "AWS Access Key": 24,
    "AWS Secret Key": 25,
    "Google API Key": 22,
    "GitHub Personal Access Token": 23,
    "GitHub Fine-grained Token": 23,
    "GitHub OAuth Token": 22,
    "Slack Token": 20,
    "Slack Webhook URL": 18,
    "JSON Web Token": 20,
    "Private Key": 25,
    "API Key": 18,
    "Secret Key": 20,
    "Password": 18,
    "Authorization Token": 22,
    "Bearer Token": 22,
    "Database Connection String": 23,
    "SendGrid API Key": 21,
    "Stripe Secret Key": 25,
    "Stripe Publishable Key": 12,
    "Twilio API Key": 21,
    "Access Token": 20,
    "High Entropy String": 12,
    "UUID/API Key": 8,
    "Generic Secret": 15,
}

# Exposure type severity weights (0-25 scale)
EXPOSURE_WEIGHTS: Dict[str, float] = {
    ExposureType.NETWORK_REQUEST.value: 25,
    ExposureType.AUTH_HEADER.value: 24,
    ExposureType.API_CALL.value: 23,
    ExposureType.DATABASE.value: 15,
    ExposureType.CONFIG_PROPAGATION.value: 12,
    ExposureType.FILE_WRITE.value: 14,
    ExposureType.LOG_OUTPUT.value: 10,
    ExposureType.CONSOLE_OUTPUT.value: 8,
    ExposureType.UNKNOWN.value: 5,
}


def calculate_risk_score(finding: Finding) -> RiskBreakdown:
    """
    Calculate a transparent risk score for a finding.

    The score is broken down into four components, each contributing
    up to 25 points for a maximum total of 100.
    """
    breakdown = RiskBreakdown()
    explanations = []

    # ── Component 1: Detection Confidence (0-25) ────────────────────

    confidence = finding.confidence
    detection_score = min(25, confidence * 25)

    # Boost for multi-method detection
    if len(finding.detection_methods) >= 3:
        detection_score = min(25, detection_score + 5)
        explanations.append(f"Multi-method detection ({', '.join(finding.detection_methods)}) → boosted confidence")
    elif len(finding.detection_methods) >= 2:
        detection_score = min(25, detection_score + 3)

    # Boost for high entropy supporting evidence
    if finding.entropy_score > 4.5:
        detection_score = min(25, detection_score + 2)
        explanations.append(f"High entropy ({finding.entropy_score:.2f}) supports authenticity")

    breakdown.detection_confidence_score = round(detection_score, 1)

    # ── Component 2: Secret Sensitivity (0-25) ──────────────────────

    sensitivity = SECRET_TYPE_WEIGHTS.get(finding.secret_type, 15)
    breakdown.secret_sensitivity_score = round(sensitivity, 1)
    explanations.append(f"Secret type '{finding.secret_type}' sensitivity: {sensitivity}/25")

    # ── Component 3: Exposure Severity (0-25) ────────────────────────

    if finding.exposure_sink:
        exposure_score = EXPOSURE_WEIGHTS.get(
            finding.exposure_sink.sink_type.value, 5
        )
        explanations.append(
            f"Exposure via '{finding.exposure_sink.sink_type.value}' → severity: {exposure_score}/25"
        )
    else:
        exposure_score = 3  # Minimal score for unexposed secrets
        explanations.append("No identified exposure sink → minimal exposure risk")

    breakdown.exposure_severity_score = round(exposure_score, 1)

    # ── Component 4: Propagation Certainty (0-25) ────────────────────

    propagation_score = 5  # Base score

    if finding.reconstruction_status == ReconstructionStatus.FULL:
        propagation_score += 10
        explanations.append("Fully reconstructed secret → high propagation certainty")
    elif finding.reconstruction_status == ReconstructionStatus.PARTIAL:
        propagation_score += 5
        explanations.append("Partially reconstructed → moderate propagation certainty")

    if finding.propagation_path and len(finding.propagation_path) > 1:
        path_bonus = min(10, len(finding.propagation_path) * 2)
        propagation_score += path_bonus
        explanations.append(
            f"Propagation path length {len(finding.propagation_path)} → +{path_bonus} certainty"
        )

    propagation_score = min(25, propagation_score)
    breakdown.propagation_certainty_score = round(propagation_score, 1)

    # ── Total Score & Severity ───────────────────────────────────────

    total = (
        breakdown.detection_confidence_score +
        breakdown.secret_sensitivity_score +
        breakdown.exposure_severity_score +
        breakdown.propagation_certainty_score
    )

    breakdown.total_score = round(total, 1)

    # Classify severity
    if total >= 80:
        breakdown.severity = Severity.CRITICAL
    elif total >= 60:
        breakdown.severity = Severity.HIGH
    elif total >= 30:
        breakdown.severity = Severity.MEDIUM
    else:
        breakdown.severity = Severity.LOW

    breakdown.explanation = " | ".join(explanations)

    return breakdown


def score_finding(finding: Finding) -> Finding:
    """
    Calculate and attach risk score to a finding.
    Returns the modified finding.
    """
    breakdown = calculate_risk_score(finding)
    finding.risk_breakdown = breakdown
    finding.risk_score = breakdown.total_score
    finding.severity = breakdown.severity
    return finding
