"""
Shannon Entropy Analyzer
Calculates information entropy to identify high-entropy strings
that may be secrets or tokens. Used as a supporting signal
alongside regex detection and context analysis.
"""

import math
import re
from typing import List, Optional
from .models import DetectionCandidate


# Default entropy thresholds (configurable)
DEFAULT_HEX_THRESHOLD = 3.0     # For hex strings
DEFAULT_BASE64_THRESHOLD = 4.0  # For base64/alphanumeric strings
DEFAULT_GENERAL_THRESHOLD = 4.5 # For general strings

# Minimum string length to consider for entropy analysis
MIN_STRING_LENGTH = 16
MAX_STRING_LENGTH = 256

# Context keywords that boost suspicion when found near high-entropy strings
CREDENTIAL_CONTEXT_KEYWORDS = {
    'api', 'key', 'secret', 'token', 'password', 'passwd', 'pwd',
    'auth', 'credential', 'bearer', 'private', 'access', 'encrypt',
    'hash', 'signature', 'cert', 'certificate', 'oauth', 'jwt',
    'connection', 'database', 'db_', 'mongo', 'redis', 'mysql',
    'postgres', 'webhook', 'slack', 'stripe', 'twilio', 'sendgrid',
    'aws', 'gcp', 'azure', 'cloud', 'heroku',
}


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string.
    Higher entropy indicates more randomness, common in secrets/tokens.

    Formula: H = -Σ p(x) * log2(p(x))
    where p(x) is the probability of character x appearing.
    """
    if not data:
        return 0.0

    # Count character frequencies
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    length = len(data)
    entropy = 0.0

    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def is_hex_string(s: str) -> bool:
    """Check if a string appears to be hexadecimal."""
    return bool(re.match(r'^[0-9a-fA-F]+$', s))


def is_base64_string(s: str) -> bool:
    """Check if a string appears to be base64 encoded."""
    return bool(re.match(r'^[A-Za-z0-9+/=\-_]+$', s))


def get_entropy_threshold(value: str) -> float:
    """
    Get the appropriate entropy threshold based on the string type.
    Hex strings have a lower maximum entropy than base64 strings.
    """
    if is_hex_string(value):
        return DEFAULT_HEX_THRESHOLD
    elif is_base64_string(value):
        return DEFAULT_BASE64_THRESHOLD
    return DEFAULT_GENERAL_THRESHOLD


def has_credential_context(line: str, surrounding_lines: List[str] = None) -> bool:
    """
    Check if the line or surrounding context contains credential-related keywords.
    This boosts confidence that a high-entropy string is actually a secret.
    """
    search_text = line.lower()
    if surrounding_lines:
        search_text += ' '.join(l.lower() for l in surrounding_lines)

    return any(keyword in search_text for keyword in CREDENTIAL_CONTEXT_KEYWORDS)


def extract_strings_from_line(line: str) -> List[str]:
    """
    Extract quoted string literals from a line of code.
    Supports single quotes, double quotes, and backtick strings.
    """
    strings = []
    # Match quoted strings
    for match in re.finditer(r'''["'`]([^"'`\n]{16,256})["'`]''', line):
        strings.append(match.group(1))
    return strings


def analyze_entropy(
    content: str,
    file_path: str,
    hex_threshold: float = DEFAULT_HEX_THRESHOLD,
    base64_threshold: float = DEFAULT_BASE64_THRESHOLD,
    general_threshold: float = DEFAULT_GENERAL_THRESHOLD,
    min_length: int = MIN_STRING_LENGTH,
) -> List[DetectionCandidate]:
    """
    Analyze strings in source code for high Shannon entropy.

    Entropy alone is NOT sufficient for detection. This function
    assigns higher confidence when high-entropy strings appear
    in credential-related contexts.

    Args:
        content: Source code content
        file_path: Path to the file
        hex_threshold: Entropy threshold for hex strings
        base64_threshold: Entropy threshold for base64 strings
        general_threshold: Entropy threshold for other strings
        min_length: Minimum string length to analyze

    Returns:
        List of DetectionCandidate objects for high-entropy strings
    """
    candidates: List[DetectionCandidate] = []
    lines = content.split('\n')

    for line_idx, line in enumerate(lines):
        # Skip comments (basic heuristic)
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*'):
            continue

        # Extract string literals from the line
        strings = extract_strings_from_line(line)

        for string_value in strings:
            if len(string_value) < min_length or len(string_value) > MAX_STRING_LENGTH:
                continue

            entropy = calculate_shannon_entropy(string_value)

            # Determine threshold based on string type
            if is_hex_string(string_value):
                threshold = hex_threshold
            elif is_base64_string(string_value):
                threshold = base64_threshold
            else:
                threshold = general_threshold

            if entropy < threshold:
                continue

            # Check surrounding context for credential keywords
            context_start = max(0, line_idx - 3)
            context_end = min(len(lines), line_idx + 4)
            surrounding = lines[context_start:context_end]
            code_context = '\n'.join(surrounding)

            has_context = has_credential_context(line, surrounding)

            # Calculate confidence:
            # - Higher entropy → higher confidence
            # - Credential context → boost confidence
            # - Without context, entropy alone gets lower confidence
            base_confidence = min(0.4, (entropy - threshold) / 3.0)

            if has_context:
                confidence = min(0.85, base_confidence + 0.35)
            else:
                confidence = min(0.5, base_confidence)

            candidate = DetectionCandidate(
                value=string_value,
                file_path=file_path,
                line_number=line_idx + 1,
                secret_type="High Entropy String",
                detection_method="entropy",
                confidence=confidence,
                entropy_score=entropy,
                code_context=code_context,
            )

            candidates.append(candidate)

    return candidates
