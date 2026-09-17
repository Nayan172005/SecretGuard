"""
Regex-Based Secret Detector
Detects common secret patterns using configurable regular expressions.
Each pattern includes a confidence level and secret type classification.
"""

import re
from typing import List, Dict, Tuple
from .models import DetectionCandidate


# Each pattern: (name, regex, secret_type, confidence)
# Confidence ranges from 0.0 to 1.0
SECRET_PATTERNS: List[Dict] = [
    {
        "name": "AWS Access Key",
        "pattern": r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        "secret_type": "AWS Access Key",
        "confidence": 0.9,
    },
    {
        "name": "AWS Secret Key",
        "pattern": r'(?i)(?:aws[_\-]?secret[_\-]?(?:access[_\-]?)?key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
        "secret_type": "AWS Secret Key",
        "confidence": 0.85,
    },
    {
        "name": "Google API Key",
        "pattern": r'AIza[0-9A-Za-z\-_]{10,}',
        "secret_type": "Google API Key",
        "confidence": 0.9,
    },
    {
        "name": "GitHub Token (Classic)",
        "pattern": r'ghp_[0-9a-zA-Z]{36}',
        "secret_type": "GitHub Personal Access Token",
        "confidence": 0.95,
    },
    {
        "name": "GitHub Token (Fine-grained)",
        "pattern": r'github_pat_[0-9a-zA-Z_]{82}',
        "secret_type": "GitHub Fine-grained Token",
        "confidence": 0.95,
    },
    {
        "name": "GitHub OAuth",
        "pattern": r'gho_[0-9a-zA-Z]{36}',
        "secret_type": "GitHub OAuth Token",
        "confidence": 0.9,
    },
    {
        "name": "Slack Token",
        "pattern": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}',
        "secret_type": "Slack Token",
        "confidence": 0.9,
    },
    {
        "name": "Slack Webhook",
        "pattern": r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}',
        "secret_type": "Slack Webhook URL",
        "confidence": 0.9,
    },
    {
        "name": "JWT",
        "pattern": r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
        "secret_type": "JSON Web Token",
        "confidence": 0.8,
    },
    {
        "name": "Private Key Header",
        "pattern": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "secret_type": "Private Key",
        "confidence": 0.95,
    },
    {
        "name": "Generic API Key Assignment",
        "pattern": r'(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9\-_\.]{16,})["\']',
        "secret_type": "API Key",
        "confidence": 0.7,
    },
    {
        "name": "Generic Secret Assignment",
        "pattern": r'(?i)(?:secret|secret[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9\-_\.]{16,})["\']',
        "secret_type": "Secret Key",
        "confidence": 0.7,
    },
    {
        "name": "Password Assignment",
        "pattern": r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']',
        "secret_type": "Password",
        "confidence": 0.6,
    },
    {
        "name": "Authorization Header",
        "pattern": r'(?i)(?:authorization|auth[_\-]?token|bearer[_\-]?token)\s*[=:]\s*["\']([A-Za-z0-9\-_\.]+)["\']',
        "secret_type": "Authorization Token",
        "confidence": 0.75,
    },
    {
        "name": "Bearer Token",
        "pattern": r'["\']Bearer\s+([A-Za-z0-9\-_\.]{20,})["\']',
        "secret_type": "Bearer Token",
        "confidence": 0.8,
    },
    {
        "name": "Database Connection String",
        "pattern": r'(?:mongodb|postgres|mysql|redis|amqp)(?:\+\w+)?://[^\s"\']+',
        "secret_type": "Database Connection String",
        "confidence": 0.85,
    },
    {
        "name": "Heroku API Key",
        "pattern": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        "secret_type": "UUID/API Key",
        "confidence": 0.3,  # UUIDs are common, low confidence without context
    },
    {
        "name": "SendGrid API Key",
        "pattern": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
        "secret_type": "SendGrid API Key",
        "confidence": 0.9,
    },
    {
        "name": "Stripe Secret Key",
        "pattern": r'sk_live_[0-9a-zA-Z]{24,}',
        "secret_type": "Stripe Secret Key",
        "confidence": 0.95,
    },
    {
        "name": "Stripe Publishable Key",
        "pattern": r'pk_live_[0-9a-zA-Z]{24,}',
        "secret_type": "Stripe Publishable Key",
        "confidence": 0.7,
    },
    {
        "name": "Twilio API Key",
        "pattern": r'SK[0-9a-fA-F]{32}',
        "secret_type": "Twilio API Key",
        "confidence": 0.7,
    },
    {
        "name": "Generic Token in Variable",
        "pattern": r'(?i)(?:token|access_token|auth_token)\s*[=:]\s*["\']([A-Za-z0-9\-_\.]{20,})["\']',
        "secret_type": "Access Token",
        "confidence": 0.65,
    },
]


def _extract_assignment_variable(line: str) -> str:
    """Return the variable assigned on a simple source-code line."""
    match = re.match(
        r'\s*(?:(?:const|let|var|export|final|static)\s+)?'
        r'([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?[=:]',
        line,
    )
    return match.group(1) if match else ""


def _classify_matched_value(value: str, default_type: str) -> str:
    """Prefer concrete provider signatures over generic assignment patterns."""
    if value.startswith("AIza"):
        return "Google API Key"
    if value.startswith("ghp_"):
        return "GitHub Personal Access Token"
    if value.startswith("github_pat_"):
        return "GitHub Fine-grained Token"
    if value.startswith("sk_live_"):
        return "Stripe Secret Key"
    if value.startswith(("AKIA", "ASIA", "AIDA", "AROA")):
        return "AWS Access Key"
    return default_type


def detect_secrets_in_content(
    content: str,
    file_path: str,
    patterns: List[Dict] = None,
) -> List[DetectionCandidate]:
    """
    Scan content for secret patterns using regex matching.

    Args:
        content: Source code content to scan
        file_path: Path to the file being scanned
        patterns: Optional custom patterns (defaults to SECRET_PATTERNS)

    Returns:
        List of DetectionCandidate objects for matches found
    """
    if patterns is None:
        patterns = SECRET_PATTERNS

    candidates: List[DetectionCandidate] = []
    lines = content.split('\n')

    for pattern_def in patterns:
        regex = re.compile(pattern_def["pattern"])

        for line_idx, line in enumerate(lines):
            for match in regex.finditer(line):
                # Extract the matched value - prefer captured group over full match
                if match.groups():
                    matched_value = match.group(1)
                else:
                    matched_value = match.group(0)

                # Get surrounding context (3 lines before and after)
                context_start = max(0, line_idx - 3)
                context_end = min(len(lines), line_idx + 4)
                code_context = '\n'.join(lines[context_start:context_end])

                candidate = DetectionCandidate(
                    value=matched_value,
                    file_path=file_path,
                    line_number=line_idx + 1,  # 1-indexed
                    column=match.start() + 1,
                    secret_type=_classify_matched_value(
                        matched_value, pattern_def["secret_type"]
                    ),
                    detection_method="regex",
                    confidence=pattern_def["confidence"],
                    context_variable=_extract_assignment_variable(line),
                    code_context=code_context,
                )

                candidates.append(candidate)

    return candidates


def detect_secrets_in_file(file_path: str, content: str) -> List[DetectionCandidate]:
    """
    Convenience wrapper for scanning a single file's content.
    """
    return detect_secrets_in_content(content, file_path)
