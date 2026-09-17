"""
Data models for the Secret Detection Engine.

These dataclasses define the structure for all findings, propagation paths,
exposure sinks, and risk assessments used throughout the detection pipeline.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
import uuid
import time


class Severity(Enum):
    """Finding severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ReconstructionStatus(Enum):
    """Status of secret reconstruction from fragments."""
    FULL = "FULL"           # All fragments statically resolved
    PARTIAL = "PARTIAL"     # Some fragments contain dynamic/unresolved values
    NONE = "NONE"           # No reconstruction attempted (direct detection)
    UNRESOLVED = "UNRESOLVED"  # Reconstruction attempted but could not resolve


class ExposureType(Enum):
    """Classification of how a secret is exposed/used."""
    NETWORK_REQUEST = "External Network Request"
    AUTH_HEADER = "Authentication Header"
    API_CALL = "API Call"
    DATABASE = "Database Storage"
    FILE_WRITE = "File Write"
    LOG_OUTPUT = "Log/Debug Output"
    CONSOLE_OUTPUT = "Console Output"
    CONFIG_PROPAGATION = "Configuration Propagation"
    UNKNOWN = "Unknown Exposure"


class SinkRisk(Enum):
    """Risk level of an exposure sink."""
    HIGH = "HIGH"       # External network, auth headers, API calls
    MEDIUM = "MEDIUM"   # Database, config propagation
    LOW = "LOW"         # Local file, debug output


@dataclass
class SecretFragment:
    """Represents a fragment of a potentially constructed secret."""
    variable_name: str
    value: str
    file_path: str
    line_number: int
    is_resolved: bool = True  # False if value is dynamic/unknown


@dataclass
class PropagationNode:
    """A node in the propagation graph showing how a secret flows through code."""
    variable: str
    file_path: str
    line_number: int
    operation: str  # e.g., "assignment", "concatenation", "function_arg", "dict_value"
    code_snippet: str = ""


@dataclass
class PropagationEdge:
    """An edge in the propagation graph representing value flow."""
    source_variable: str
    target_variable: str
    edge_type: str  # e.g., "assignment", "concatenation", "parameter_pass"


@dataclass
class PropagationGraph:
    """Graph representing how a secret propagates through program flow."""
    nodes: List[PropagationNode] = field(default_factory=list)
    edges: List[PropagationEdge] = field(default_factory=list)

    def add_node(self, node: PropagationNode):
        self.nodes.append(node)

    def add_edge(self, edge: PropagationEdge):
        self.edges.append(edge)

    def get_path(self) -> List[str]:
        """Get the propagation path as a list of variable names."""
        return [node.variable for node in self.nodes]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [
                {
                    "variable": n.variable,
                    "file": n.file_path,
                    "line": n.line_number,
                    "operation": n.operation,
                    "code_snippet": n.code_snippet
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "source": e.source_variable,
                    "target": e.target_variable,
                    "type": e.edge_type
                }
                for e in self.edges
            ],
            "path": self.get_path()
        }


@dataclass
class ExposureSink:
    """Represents where a secret is eventually used/exposed."""
    sink_type: ExposureType
    risk_level: SinkRisk
    function_name: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str = ""


@dataclass
class RiskBreakdown:
    """Transparent breakdown of how risk score was calculated."""
    detection_confidence_score: float = 0.0
    secret_sensitivity_score: float = 0.0
    exposure_severity_score: float = 0.0
    propagation_certainty_score: float = 0.0
    total_score: float = 0.0
    severity: Severity = Severity.LOW
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection_confidence": self.detection_confidence_score,
            "secret_sensitivity": self.secret_sensitivity_score,
            "exposure_severity": self.exposure_severity_score,
            "propagation_certainty": self.propagation_certainty_score,
            "total_score": self.total_score,
            "severity": self.severity.value,
            "explanation": self.explanation
        }


@dataclass
class DetectionCandidate:
    """A candidate secret found by one of the detection mechanisms."""
    value: str
    file_path: str
    line_number: int
    column: int = 0
    secret_type: str = "Generic Secret"
    detection_method: str = "regex"  # regex, entropy, reconstruction
    confidence: float = 0.5
    entropy_score: float = 0.0
    context_variable: str = ""
    code_context: str = ""
    is_false_positive: bool = False


@dataclass
class Finding:
    """Complete finding with all analysis results."""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    secret_type: str = "Generic Secret"
    file_path: str = ""
    line_number: int = 0
    code_context: str = ""
    masked_secret: str = ""
    raw_secret: str = ""  # Internal use only, never exposed to UI
    detection_methods: List[str] = field(default_factory=list)
    confidence: float = 0.0
    entropy_score: float = 0.0

    # Reconstruction (Core Novelty)
    reconstruction_status: ReconstructionStatus = ReconstructionStatus.NONE
    fragments: List[SecretFragment] = field(default_factory=list)
    reconstructed_value_masked: str = ""

    # Propagation (Core Novelty)
    propagation_graph: Optional[PropagationGraph] = None
    propagation_path: List[str] = field(default_factory=list)

    # Exposure (Core Novelty)
    exposure_sink: Optional[ExposureSink] = None
    exposure_type: str = ""

    # Risk
    risk_breakdown: Optional[RiskBreakdown] = None
    risk_score: float = 0.0
    severity: Severity = Severity.LOW

    # AI Analysis
    ai_explanation: str = ""
    ai_remediation: str = ""
    ai_impact: str = ""
    ai_confidence_assessment: str = ""
    ai_executive_summary: str = ""
    ai_analysis_status: str = "pending"  # pending, completed, unavailable

    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for API responses."""
        return {
            "finding_id": self.finding_id,
            "secret_type": self.secret_type,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_context": self.code_context,
            "masked_secret": self.masked_secret,
            "detection_methods": self.detection_methods,
            "confidence": self.confidence,
            "entropy_score": round(self.entropy_score, 3),
            "reconstruction_status": self.reconstruction_status.value,
            "fragments": [
                {
                    "variable": f.variable_name,
                    "value": mask_secret(f.value) if f.is_resolved else "[DYNAMIC]",
                    "file": f.file_path,
                    "line": f.line_number,
                    "resolved": f.is_resolved
                }
                for f in self.fragments
            ],
            "reconstructed_value_masked": self.reconstructed_value_masked,
            "propagation_path": self.propagation_path,
            "propagation_graph": self.propagation_graph.to_dict() if self.propagation_graph else None,
            "exposure_sink": {
                "type": self.exposure_sink.sink_type.value,
                "risk_level": self.exposure_sink.risk_level.value,
                "function": self.exposure_sink.function_name,
                "file": self.exposure_sink.file_path,
                "line": self.exposure_sink.line_number,
                "code": self.exposure_sink.code_snippet,
                "description": self.exposure_sink.description
            } if self.exposure_sink else None,
            "exposure_type": self.exposure_type,
            "risk_score": round(self.risk_score, 1),
            "risk_breakdown": self.risk_breakdown.to_dict() if self.risk_breakdown else None,
            "severity": self.severity.value,
            "ai_explanation": self.ai_explanation,
            "ai_remediation": self.ai_remediation,
            "ai_impact": self.ai_impact,
            "ai_confidence_assessment": self.ai_confidence_assessment,
            "ai_executive_summary": self.ai_executive_summary,
            "ai_analysis_status": self.ai_analysis_status,
            "timestamp": self.timestamp
        }


@dataclass
class ScanResult:
    """Complete result of scanning a repository."""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    repository_name: str = ""
    total_files: int = 0
    total_lines: int = 0
    files_scanned: int = 0
    scan_duration: float = 0.0
    candidates_found: int = 0
    secrets_reconstructed: int = 0
    findings: List[Finding] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=lambda: {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
    })
    average_risk_score: float = 0.0
    status: str = "completed"
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "repository_name": self.repository_name,
            "total_files": self.total_files,
            "total_lines": self.total_lines,
            "files_scanned": self.files_scanned,
            "scan_duration": round(self.scan_duration, 2),
            "candidates_found": self.candidates_found,
            "secrets_reconstructed": self.secrets_reconstructed,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "severity_counts": self.severity_counts,
            "average_risk_score": round(self.average_risk_score, 1),
            "status": self.status,
            "error": self.error
        }


def mask_secret(secret: str, visible_chars: int = 4) -> str:
    """
    Mask a secret value, showing only the first and last few characters.
    Example: "AKIATEST1234ABCDE" -> "AKIA**********CDE"
    """
    if not secret:
        return ""
    if len(secret) <= visible_chars * 2:
        return "*" * len(secret)
    return secret[:visible_chars] + "*" * (len(secret) - visible_chars * 2) + secret[-visible_chars:]
