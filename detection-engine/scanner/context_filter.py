"""
Context Filter Module
Reduces false positives by examining the surrounding code context,
variable names, and string characteristics to determine whether
a detection candidate is likely a real secret or a placeholder/example.
"""

import re
from typing import List, Set
from .models import DetectionCandidate
from .secret_validator import is_environment_variable_usage


# Strings that are clearly placeholder/example values
PLACEHOLDER_PATTERNS: List[str] = [
    r'(?i)^example',
    r'(?i)^your[_\-]',
    r'(?i)^my[_\-]',
    r'(?i)^test[_\-]?',
    r'(?i)^dummy',
    r'(?i)^fake',
    r'(?i)^placeholder',
    r'(?i)^sample',
    r'(?i)^demo[_\-]?',
    r'(?i)^insert[_\-]',
    r'(?i)^replace[_\-]',
    r'(?i)^change[_\-]',
    r'(?i)^put[_\-]',
    r'(?i)^enter[_\-]',
    r'(?i)^xxx',
    r'(?i)^todo',
    r'(?i)^fixme',
    r'(?i)^temp',
    r'(?i)^default',
]

# Exact values commonly seen as placeholders
PLACEHOLDER_VALUES: Set[str] = {
    'your_api_key',
    'your_api_key_here',
    'your-api-key',
    'your-api-key-here',
    'api_key_here',
    'api-key-here',
    'insert_api_key',
    'insert-api-key',
    'example_api_key',
    'example-api-key',
    'test_api_key',
    'test-api-key',
    'my_api_key',
    'my-api-key',
    'sk_test_',
    'pk_test_',
    'your_secret_key',
    'your_token',
    'your_password',
    'password123',
    'password',
    'changeme',
    'change_me',
    'xxxxxxxx',
    'xxxxxxxxxxxx',
    'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    '0000000000000000',
    '1111111111111111',
    '1234567890123456',
    'abcdefghijklmnop',
    'abcdefghijklmnopqrstuvwxyz',
    'aabbccddeeffgghh',
    'hello world',
    'hello_world',
    'foo_bar_baz',
    'lorem ipsum',
    'none',
    'null',
    'undefined',
    'n/a',
    'na',
    'tbd',
    'todo',
}

# Additional placeholder substrings that indicate non-real values
PLACEHOLDER_SUBSTRINGS = [
    'yourkeyhere', 'yourtokenhere', 'yoursecrethere',
    'your_key_here', 'your_token_here', 'your_secret_here',
    'example_token', 'example_key', 'example_secret',
    'placeholder', 'changeme', 'insertkeyhere',
]

# Patterns indicating documentation/comment context
DOCUMENTATION_INDICATORS: List[str] = [
    r'(?i)#\s*example',
    r'(?i)//\s*example',
    r'(?i)/\*\s*example',
    r'(?i)#\s*todo',
    r'(?i)#\s*replace',
    r'(?i)#\s*note',
    r'(?i)#\s*documentation',
    r'(?i)#\s*sample',
    r'(?i)#\s*test',
    r'(?i)#\s*dummy',
    r'(?i)#\s*fake',
    r'(?i)//\s*todo',
    r'(?i)//\s*replace',
    r'(?i)//\s*fixme',
    r'(?i)\*\s*@example',
    r'(?i)\*\s*@param',
    r'(?i)>>>',  # Python doctest
]

# Repetitive character patterns (likely not real secrets)
REPETITIVE_PATTERN = re.compile(r'^(.)\1{7,}$|^(.{1,3})\2{4,}$')

# Common variable names that suggest a value is a configuration placeholder
CONFIG_PLACEHOLDER_VARS = re.compile(
    r'(?i)(default|template|schema|example|placeholder|mock|stub|fixture)'
)


def is_placeholder_value(value: str) -> bool:
    """Check if a value matches known placeholder patterns."""
    lower_value = value.lower().strip()

    # Check exact matches
    if lower_value in PLACEHOLDER_VALUES:
        return True

    # Check placeholder patterns
    for pattern in PLACEHOLDER_PATTERNS:
        if re.match(pattern, value):
            return True

    # Check placeholder substrings (e.g., "AIzaSyYourKeyHere")
    for substr in PLACEHOLDER_SUBSTRINGS:
        if substr in lower_value:
            return True

    # Check repetitive patterns (e.g., "aaaaaaaaaa", "abcabcabc")
    if REPETITIVE_PATTERN.match(value):
        return True

    # Check if it's all the same character
    if len(set(value.replace('-', '').replace('_', ''))) <= 2:
        return True

    return False


def is_documentation_context(code_context: str) -> bool:
    """
    Check if the code context suggests this is documentation,
    a comment, or an example.
    """
    for pattern in DOCUMENTATION_INDICATORS:
        if re.search(pattern, code_context):
            return True

    # Check if the matched line itself is a comment with an example
    lines = code_context.split('\n')
    middle_idx = len(lines) // 2
    if middle_idx < len(lines):
        mid_line = lines[middle_idx].strip()
        # Lines starting with # or // that contain 'Example:' or 'e.g.'
        if mid_line.startswith('#') or mid_line.startswith('//'):
            if any(kw in mid_line.lower() for kw in ['example', 'e.g.', 'sample', 'demo']):
                return True

    # Check if the matched line is inside a block comment
    in_block_comment = False
    for line in lines:
        stripped = line.strip()
        if '"""' in stripped or "'''" in stripped:
            in_block_comment = not in_block_comment
        if '/*' in stripped:
            in_block_comment = True
        if '*/' in stripped:
            in_block_comment = False

    return in_block_comment


def is_test_file(file_path: str) -> bool:
    """Check if the file appears to be a test file."""
    lower_path = file_path.lower()
    test_indicators = [
        '/test/', '/tests/', '/spec/', '/specs/',
        'test_', '_test.', '.test.', '.spec.',
        'fixture', 'mock', '__test__',
        '/testing/', '/testdata/',
    ]
    return any(indicator in lower_path for indicator in test_indicators)


def get_variable_context(line: str) -> str:
    """
    Extract the variable name from an assignment line.
    E.g., 'api_key = "value"' returns 'api_key'
    """
    # Python/JS/Go style: var_name = "value"
    match = re.match(r'\s*(?:(?:const|let|var|export)\s+)?(\w+)\s*[=:]\s*', line)
    if match:
        return match.group(1)
    return ""


def _get_candidate_line(candidate: DetectionCandidate) -> str:
    """Locate the actual matched source line inside a candidate context."""
    if not candidate.code_context:
        return ""

    lines = candidate.code_context.split('\n')
    for line in lines:
        if candidate.value and candidate.value in line:
            return line

    # Fall back to the previous center-line behavior when the value was
    # captured separately from the literal text in context.
    return lines[len(lines) // 2] if lines else ""


def filter_candidates(
    candidates: List[DetectionCandidate],
    allow_test_files: bool = False,
) -> List[DetectionCandidate]:
    """
    Filter detection candidates to reduce false positives.

    Applies multiple heuristics:
    1. Remove placeholder/example values
    2. Reduce confidence for documentation context
    3. Reduce confidence for test files
    4. Mark clear false positives

    Args:
        candidates: List of detection candidates from regex/entropy
        allow_test_files: If True, don't filter out test file findings

    Returns:
        Filtered list with updated confidence and false_positive flags
    """
    filtered: List[DetectionCandidate] = []

    for candidate in candidates:
        # Check if value is a known placeholder
        if is_placeholder_value(candidate.value):
            candidate.is_false_positive = True
            candidate.confidence *= 0.1
            continue  # Skip known placeholders entirely

        # Check if value comes from environment variable
        if is_environment_variable_usage(candidate.code_context):
            candidate.is_false_positive = True
            candidate.confidence *= 0.05
            continue  # Environment variables are safe sources

        # Check documentation context
        if is_documentation_context(candidate.code_context):
            candidate.confidence *= 0.3
            if candidate.confidence < 0.2:
                candidate.is_false_positive = True
                continue

        # Reduce confidence for test files
        if is_test_file(candidate.file_path) and not allow_test_files:
            candidate.confidence *= 0.5

        # Check variable context - boost if variable name is suspicious
        var_name = candidate.context_variable or get_variable_context(
            _get_candidate_line(candidate)
        )
        if var_name:
            candidate.context_variable = var_name
            # Check if the variable name suggests a config placeholder
            if CONFIG_PLACEHOLDER_VARS.search(var_name):
                candidate.confidence *= 0.4

        # Skip very low confidence candidates
        if candidate.confidence < 0.15:
            candidate.is_false_positive = True
            continue

        filtered.append(candidate)

    return filtered
