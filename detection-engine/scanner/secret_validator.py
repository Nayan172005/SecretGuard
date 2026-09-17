"""
Secret Validator — Post-Reconstruction Validation Stage

After reconstruction assembles candidate strings, this module determines
whether the result is actually secret-like or just normal string
concatenation (e.g., "Hello" + " " + "World").

Validation signals:
  A. Known secret pattern (AKIA..., ghp_..., AIza..., sk_live_..., etc.)
  B. Secret-like variable name (api_key, secret, password, token, etc.)
  C. Entropy analysis (high entropy = more likely a real secret)
  D. Semantic/content classification (reject natural language, URLs, etc.)
  E. Code context (surrounding code suggests credential usage)

IMPORTANT: This does NOT disable reconstruction. It validates the output
of reconstruction to separate genuine secrets from normal string ops.
"""

import re
import math
from typing import Optional


# ─── Secret-Like Variable Name Patterns ─────────────────────────────────

SECRET_VARIABLE_PATTERNS = re.compile(
    r'(?i)^(?:.*_)?'
    r'(?:api[_\-]?key|apikey|secret(?:[_\-]?key)?|password|passwd|pwd|'
    r'token|access[_\-]?token|auth[_\-]?token|bearer|credential|'
    r'private[_\-]?key|aws[_\-]?(?:access|secret)|github[_\-]?token|'
    r'stripe[_\-]?(?:key|secret)|sendgrid|twilio|slack[_\-]?token|'
    r'db[_\-]?(?:password|pass)|database[_\-]?(?:url|password)|'
    r'connection[_\-]?string|mongo[_\-]?uri|jwt|signing[_\-]?key|'
    r'encryption[_\-]?key|client[_\-]?secret|app[_\-]?secret)'
    r'(?:_.*)?$'
)

# Variable names that are definitely NOT secret-related
SAFE_VARIABLE_PATTERNS = re.compile(
    r'(?i)^(?:url|uri|endpoint|base[_\-]?url|api[_\-]?url|'
    r'greeting|message|name|full[_\-]?name|first[_\-]?name|last[_\-]?name|'
    r'title|description|label|text|content|body|'
    r'path|route|prefix|suffix|'
    r'version|env|environment|mode|'
    r'host|hostname|domain|port|'
    r'email|username|user[_\-]?name|display[_\-]?name)$'
)

# ─── Known Secret Patterns ──────────────────────────────────────────────

SECRET_VALUE_PATTERNS = [
    (r'^(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}', "AWS Access Key"),
    (r'^AIza[0-9A-Za-z\-_]{10,}', "Google API Key"),
    (r'^ghp_[0-9a-zA-Z]{20,}', "GitHub Personal Access Token"),
    (r'^github_pat_[0-9a-zA-Z_]{20,}', "GitHub Fine-grained Token"),
    (r'^gho_[0-9a-zA-Z]{20,}', "GitHub OAuth Token"),
    (r'^sk_live_[0-9a-zA-Z]{20,}', "Stripe Secret Key"),
    (r'^pk_live_[0-9a-zA-Z]{20,}', "Stripe Publishable Key"),
    (r'^SG\.[a-zA-Z0-9_-]{20,}', "SendGrid API Key"),
    (r'^SK[0-9a-fA-F]{32}', "Twilio API Key"),
    (r'^xox[baprs]-', "Slack Token"),
    (r'^eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.', "JSON Web Token"),
    (r'^-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key"),
    (r'^(?:mongodb|postgres|mysql|redis|amqp)(?:\+\w+)?://\S+:\S+@', "Database Connection String"),
    (r'^Bearer\s+[A-Za-z0-9\-_\.]{20,}', "Bearer Token"),
]

# ─── Non-Secret Content Patterns ────────────────────────────────────────

# URLs without credentials are NOT secrets
PLAIN_URL_PATTERN = re.compile(
    r'^https?://[^\s]+$'
)

# Common natural language / non-secret patterns
NATURAL_LANGUAGE_INDICATORS = [
    re.compile(r'\s'),           # Contains spaces → natural language
    re.compile(r'^[A-Z][a-z]+(?:\s+[A-Za-z]+)+$'),  # Title Case words
]

# ─── Environment Variable Patterns ──────────────────────────────────────

ENV_VAR_PATTERNS = [
    re.compile(r'os\.environ\.get\s*\('),
    re.compile(r'os\.environ\s*\['),
    re.compile(r'os\.getenv\s*\('),
    re.compile(r'process\.env\.'),
    re.compile(r'System\.getenv\s*\('),
    re.compile(r'\$ENV\{'),
    re.compile(r'getenv\s*\('),
]


def _calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
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


def matches_known_secret_pattern(value: str) -> Optional[str]:
    """
    Check if the value matches a known secret pattern.
    Returns the secret type if matched, None otherwise.
    """
    for pattern, secret_type in SECRET_VALUE_PATTERNS:
        if re.match(pattern, value):
            return secret_type
    return None


def is_secret_like_variable(variable_name: str) -> bool:
    """Check if a variable name suggests it holds a secret."""
    if not variable_name:
        return False
    return bool(SECRET_VARIABLE_PATTERNS.match(variable_name))


def is_safe_variable(variable_name: str) -> bool:
    """Check if a variable name clearly indicates non-secret content."""
    if not variable_name:
        return False
    return bool(SAFE_VARIABLE_PATTERNS.match(variable_name))


def is_environment_variable_usage(code_context: str) -> bool:
    """
    Check if the code context indicates the value comes from
    an environment variable (os.environ.get, os.getenv, process.env, etc.).
    """
    if not code_context:
        return False
    for pattern in ENV_VAR_PATTERNS:
        if pattern.search(code_context):
            return True
    return False


def is_plain_url(value: str) -> bool:
    """
    Check if the value is a plain URL without embedded credentials.
    URLs like https://api.example.com/v1/users are NOT secrets.
    URLs like mongodb://user:pass@host/db ARE secrets (they embed creds).
    """
    if not PLAIN_URL_PATTERN.match(value):
        return False
    # Check for embedded credentials (user:pass@host pattern)
    if re.search(r'://[^/]+:[^/]+@', value):
        return False  # Has embedded creds → is a secret
    return True  # Plain URL → not a secret


def is_natural_language(value: str) -> bool:
    """
    Check if the value looks like natural language rather than a secret.
    Secrets are typically long alphanumeric strings without spaces.
    """
    # Contains spaces → likely natural language
    if ' ' in value:
        # But check if it could be "Bearer <token>" style
        parts = value.split()
        if len(parts) == 2 and parts[0].lower() in ('bearer', 'basic', 'token'):
            return False
        return True

    # All lowercase alphabetic with underscores → might be a placeholder or name
    if re.match(r'^[a-z_]+$', value) and len(value) < 30:
        return True

    return False


def is_placeholder_value(value: str) -> bool:
    """Check if the reconstructed value is clearly a placeholder."""
    lower = value.lower()
    placeholder_indicators = [
        'yourkeyhere', 'yourtokenhere', 'your_key_here', 'your_token_here',
        'example', 'placeholder', 'dummy', 'sample', 'test_key',
        'insert_here', 'replace_me', 'changeme', 'todo',
    ]
    for indicator in placeholder_indicators:
        if indicator in lower:
            return True

    # All same character (e.g. "xxxxxxxx")
    unique_chars = set(value.replace('-', '').replace('_', ''))
    if len(unique_chars) <= 2 and len(value) > 4:
        return True

    return False


def validate_reconstructed_secret(
    reconstructed_value: str,
    target_variable: str,
    code_context: str = "",
    fragments_count: int = 0,
) -> tuple:
    """
    Validate whether a reconstructed value is actually a secret.

    Returns:
        (is_secret: bool, confidence: float, secret_type: str, reason: str)
    """
    if not reconstructed_value:
        return False, 0.0, "None", "Empty value"

    if is_environment_variable_usage(code_context):
        return False, 0.0, "None", "Value comes from environment variable"

    if is_placeholder_value(reconstructed_value):
        return False, 0.0, "None", "Appears to be a placeholder"

    if is_plain_url(reconstructed_value):
        return False, 0.0, "None", "Plain URL without credentials"

    if is_natural_language(reconstructed_value):
        return False, 0.0, "None", "Appears to be natural language"

    confidence = 0.0
    reasons = []
    secret_type = "Reconstructed Secret"

    # ── Signal A: Known secret pattern ─────────────────────────────
    pattern_match = matches_known_secret_pattern(reconstructed_value)
    if pattern_match:
        secret_type = pattern_match
        confidence += 0.65
        reasons.append(f"Matches known pattern: {pattern_match}")

    # ── Signal B: Variable name suggests secret ────────────────────
    if is_secret_like_variable(target_variable):
        confidence += 0.25
        reasons.append(f"Variable name '{target_variable}' suggests secret")
    elif is_safe_variable(target_variable):
        confidence -= 0.4
        reasons.append(f"Variable name '{target_variable}' is non-secret")

    # ── Signal C: Entropy ──────────────────────────────────────────
    entropy = _calculate_entropy(reconstructed_value)
    if entropy > 4.0:
        confidence += 0.15
        reasons.append(f"High entropy ({entropy:.2f})")
    elif entropy < 2.5:
        confidence -= 0.2
        reasons.append(f"Low entropy ({entropy:.2f}) suggests non-secret")

    # ── Signal D: Non-secret content checks ────────────────────────

    # Plain URL without credentials
    if is_plain_url(reconstructed_value):
        confidence -= 0.6
        reasons.append("Plain URL without credentials")

    # Natural language
    if is_natural_language(reconstructed_value):
        confidence -= 0.5
        reasons.append("Appears to be natural language")

    # Placeholder
    if is_placeholder_value(reconstructed_value):
        confidence -= 0.5
        reasons.append("Appears to be a placeholder")

    # ── Signal E: Environment variable context ─────────────────────
    if is_environment_variable_usage(code_context):
        confidence -= 0.5
        reasons.append("Value comes from environment variable")

    # ── Final decision ─────────────────────────────────────────────
    is_secret = confidence >= 0.45

    # Clamp confidence to [0, 1]
    final_confidence = max(0.0, min(1.0, confidence))

    reason_str = " | ".join(reasons) if reasons else "No signals detected"

    return is_secret, final_confidence, secret_type, reason_str


def is_secret_like(value: str, variable_name: str = "", code_context: str = "") -> bool:
    """
    Convenience function: returns True if the value appears to be a secret.
    Used for quick checks without needing the full confidence breakdown.
    """
    is_secret, _, _, _ = validate_reconstructed_secret(
        value, variable_name, code_context
    )
    return is_secret
