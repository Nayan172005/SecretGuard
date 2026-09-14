"""
File Scanner Module
Recursively scans directories for supported source-code files,
filtering out binaries, build artifacts, and vendor directories.
"""

import os
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field


# Supported file extensions mapped to language names
SUPPORTED_EXTENSIONS: Dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "JavaScript (JSX)",
    ".tsx": "TypeScript (TSX)",
    ".java": "Java",
    ".c": "C",
    ".h": "C Header",
    ".cpp": "C++",
    ".hpp": "C++ Header",
    ".go": "Go",
    ".php": "PHP",
    ".rb": "Ruby",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".env": "Environment",
    ".cfg": "Config",
    ".conf": "Config",
    ".ini": "Config",
    ".toml": "TOML",
    ".properties": "Properties",
    ".xml": "XML",
    ".sh": "Shell",
    ".bash": "Shell",
    ".ps1": "PowerShell",
    ".tf": "Terraform",
    ".dockerfile": "Dockerfile",
}

# Special filenames to include regardless of extension
SPECIAL_FILENAMES: Set[str] = {
    "Dockerfile",
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.staging",
    ".gitignore",
    "Makefile",
    "docker-compose.yml",
    "docker-compose.yaml",
}

# Directories to skip entirely
SKIP_DIRECTORIES: Set[str] = {
    "node_modules",
    ".git",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "venv",
    ".venv",
    "env",
    ".env_dir",
    "build",
    "dist",
    "target",
    "out",
    "bin",
    ".idea",
    ".vscode",
    ".vs",
    ".gradle",
    ".maven",
    "vendor",
    "bower_components",
    ".next",
    ".nuxt",
    "coverage",
    ".nyc_output",
    ".cache",
    "tmp",
    "temp",
}

# Maximum file size to scan (in bytes) — default 1MB
MAX_FILE_SIZE = 1 * 1024 * 1024

# Maximum line count
MAX_LINE_COUNT = 50000


@dataclass
class ScannedFile:
    """Represents a source-code file that has been scanned."""
    path: str
    relative_path: str
    language: str
    line_count: int
    size: int
    content: str = ""
    lines: List[str] = field(default_factory=list)


def is_supported_file(filepath: str) -> bool:
    """Check if a file has a supported extension or is a special filename."""
    basename = os.path.basename(filepath).lower()

    # Check special filenames
    if basename in {s.lower() for s in SPECIAL_FILENAMES}:
        return True

    # Check file extension
    _, ext = os.path.splitext(filepath)
    return ext.lower() in SUPPORTED_EXTENSIONS


def get_language(filepath: str) -> str:
    """Determine the programming language from the file extension."""
    basename = os.path.basename(filepath).lower()

    if basename == "dockerfile":
        return "Dockerfile"
    if basename.startswith(".env"):
        return "Environment"
    if basename == "makefile":
        return "Makefile"

    _, ext = os.path.splitext(filepath)
    return SUPPORTED_EXTENSIONS.get(ext.lower(), "Unknown")


def is_likely_minified(content: str) -> bool:
    """
    Heuristic check: if the average line length is very high,
    the file is likely minified/generated.
    """
    lines = content.split('\n')
    if len(lines) < 3:
        return False
    avg_length = sum(len(l) for l in lines) / len(lines)
    return avg_length > 500  # Minified files tend to have very long lines


def is_binary_file(filepath: str) -> bool:
    """Check if a file appears to be binary."""
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(8192)
            # Check for null bytes (common in binary files)
            if b'\x00' in chunk:
                return True
            return False
    except (IOError, OSError):
        return True


def scan_directory(
    root_path: str,
    max_file_size: int = MAX_FILE_SIZE,
    max_line_count: int = MAX_LINE_COUNT,
    skip_dirs: Optional[Set[str]] = None,
) -> List[ScannedFile]:
    """
    Recursively scan a directory for supported source-code files.

    Args:
        root_path: Root directory to scan
        max_file_size: Maximum file size in bytes
        max_line_count: Maximum number of lines per file
        skip_dirs: Additional directories to skip

    Returns:
        List of ScannedFile objects with content loaded
    """
    if skip_dirs is None:
        skip_dirs = SKIP_DIRECTORIES
    else:
        skip_dirs = SKIP_DIRECTORIES | skip_dirs

    scanned_files: List[ScannedFile] = []

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Filter out directories to skip (modifying dirnames in-place
        # prevents os.walk from descending into them)
        dirnames[:] = [
            d for d in dirnames
            if d.lower() not in {s.lower() for s in skip_dirs}
        ]

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            relative_path = os.path.relpath(filepath, root_path)

            # Skip unsupported files
            if not is_supported_file(filepath):
                continue

            # Skip files that are too large
            try:
                file_size = os.path.getsize(filepath)
            except OSError:
                continue

            if file_size > max_file_size:
                continue

            if file_size == 0:
                continue

            # Skip binary files
            if is_binary_file(filepath):
                continue

            # Read file content
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except (IOError, OSError, UnicodeDecodeError):
                continue

            # Skip minified files
            if is_likely_minified(content):
                continue

            lines = content.split('\n')

            # Skip files with too many lines
            if len(lines) > max_line_count:
                continue

            language = get_language(filepath)

            scanned_files.append(ScannedFile(
                path=filepath,
                relative_path=relative_path.replace('\\', '/'),
                language=language,
                line_count=len(lines),
                size=file_size,
                content=content,
                lines=lines,
            ))

    return scanned_files


def get_scan_summary(files: List[ScannedFile]) -> Dict:
    """Generate a summary of scanned files."""
    language_counts: Dict[str, int] = {}
    total_lines = 0

    for f in files:
        language_counts[f.language] = language_counts.get(f.language, 0) + 1
        total_lines += f.line_count

    return {
        "total_files": len(files),
        "total_lines": total_lines,
        "languages": language_counts,
        "total_size_bytes": sum(f.size for f in files),
    }
