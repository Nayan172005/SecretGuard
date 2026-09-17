"""
Exposure Sink Analyzer — CORE NOVELTY MODULE

Identifies where reconstructed and tracked secrets eventually reach.
Classifies sinks by type (network, auth, file, logging, database)
and risk level (HIGH, MEDIUM, LOW).

This module examines the propagation graph's terminal nodes and
the surrounding code to determine the exposure mechanism.

CLASSIFICATION PRIORITY:
1. Function/API identity (strongest signal)
2. Specific sink type matching
3. Generic contextual classification (weakest signal)
"""

import re
import ast
from typing import List, Dict, Optional, Set
from .models import (
    ExposureSink, ExposureType, SinkRisk,
    PropagationGraph, PropagationNode
)


# ─── Sink Function Patterns ──────────────────────────────────────────────

# Functions/methods that represent network exposure sinks
NETWORK_SINKS = {
    # Python requests library
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head", "requests.options", "requests.request",
    # Python urllib
    "urllib.request", "urllib.request.urlopen", "urlopen",
    # Python httpx
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
    "httpx.patch", "httpx.request", "httpx.AsyncClient", "httpx.Client",
    # Python aiohttp
    "aiohttp.ClientSession",
    # JavaScript/Node fetch & axios
    "fetch", "axios.get", "axios.post", "axios.put", "axios.delete",
    "axios.request", "axios.patch",
    # HTTP/socket
    "http.request", "https.request", "http.get", "https.get",
    "socket.connect", "socket.send",
    # Cloud SDKs
    "boto3.client", "boto3.resource",
    "google.cloud", "azure.storage",
    # Go HTTP
    "http.Get", "http.Post", "http.NewRequest",
    # Java HTTP
    "HttpClient", "HttpURLConnection", "OkHttpClient",
    # PHP
    "curl_exec", "curl_init", "file_get_contents",
}

# Functions that represent authentication-related sinks
AUTH_SINKS = {
    "Authorization", "Bearer", "X-API-Key", "X-Api-Key",
    "x-api-key", "api-key", "apikey", "api_key",
    "authenticate", "login", "auth",
}

# Functions that represent file write sinks
FILE_SINKS = {
    "open", "write", "writelines", "fwrite",
    "fs.writeFile", "fs.writeFileSync", "fs.appendFile",
    "file_put_contents",
    "os.WriteFile", "ioutil.WriteFile",
}

# Functions that represent logging/output sinks
LOG_SINKS = {
    "print", "console.log", "console.error", "console.warn", "console.info",
    "console.debug",
    "logging.info", "logging.debug", "logging.warning", "logging.error",
    "logging.critical", "logger.info", "logger.debug", "logger.warning",
    "logger.error", "log.info", "log.debug", "log.warn", "log.error",
    "log.Println", "log.Printf", "fmt.Println", "fmt.Printf",
    "System.out.println", "System.out.print",
    "echo", "var_dump", "print_r",
    "puts", "p",
}

# Functions that represent database sinks
DB_SINKS = {
    "execute", "executemany", "cursor.execute",
    "db.query", "db.execute",
    "collection.insert", "collection.insertOne", "collection.insertMany",
    "collection.update", "collection.updateOne",
    "save", "create",
    "query",
}

# Dictionary keys that indicate authentication context
AUTH_DICT_KEYS = {
    "authorization", "auth", "bearer", "token", "api_key", "apikey",
    "api-key", "x-api-key", "x-auth-token", "access_token",
    "secret", "password", "credential",
}


def _match_function_sink(func_name: str, sink_set: set) -> bool:
    """
    Check if a function name matches any entry in a sink set.
    Matches by exact match, or by the func name containing the sink,
    or the func name ending with the last component of a dotted sink.
    """
    func_lower = func_name.lower()
    for sink in sink_set:
        sink_lower = sink.lower()
        if func_lower == sink_lower:
            return True
        if func_lower.startswith(f"{sink_lower}."):
            return True
        # Match by last component: e.g. func "get" matches "requests.get"
        parts = sink_lower.split('.')
        if len(parts) > 1 and func_lower.endswith(parts[-1]):
            # Only if the func also looks like a method call
            if '.' in func_lower:
                return True
    return False


def _get_func_name(node: ast.AST) -> str:
    """Extract a dotted function name from a Python AST call node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _get_func_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _expr_contains_name(node: ast.AST, names: Set[str]) -> bool:
    """Return True when an expression references any tainted name."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in names:
            return True
    return False


def _auth_key_from_node(node: ast.AST) -> str:
    if isinstance(node, ast.Constant):
        return str(node.value)
    if isinstance(node, ast.Str):
        return node.s
    return ""


def _line_snippet(lines: List[str], line_number: int) -> str:
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1].strip()
    return ""


def _add_unique_sink(sinks: List[ExposureSink], sink: ExposureSink):
    key = (sink.line_number, sink.sink_type.value, sink.function_name)
    if not any((s.line_number, s.sink_type.value, s.function_name) == key for s in sinks):
        sinks.append(sink)


def _analyze_python_code_for_sinks(
    content: str,
    file_path: str,
    secret_variables: Set[str],
) -> List[ExposureSink]:
    """AST-aware sink analysis for Python, including multiline calls/dicts."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    lines = content.split('\n')
    sinks: List[ExposureSink] = []
    tainted: Set[str] = set(secret_variables)

    nodes = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.Expr))
    ]
    nodes.sort(key=lambda n: getattr(n, "lineno", 0))

    for node in nodes:
        value = node.value if isinstance(node, ast.Assign) else node.value
        line_number = getattr(node, "lineno", 0)
        snippet = _line_snippet(lines, line_number)

        if isinstance(node, ast.Assign):
            targets = [t for t in node.targets if isinstance(t, ast.Name)]

            if _expr_contains_name(value, tainted):
                for target in targets:
                    tainted.add(target.id)

            if isinstance(value, ast.Dict):
                for key_node, val_node in zip(value.keys, value.values):
                    if val_node is None or not _expr_contains_name(val_node, tainted):
                        continue

                    key_name = _auth_key_from_node(key_node)
                    if key_name and key_name.lower() in AUTH_DICT_KEYS:
                        for target in targets:
                            tainted.add(target.id)
                        _add_unique_sink(sinks, ExposureSink(
                            sink_type=ExposureType.AUTH_HEADER,
                            risk_level=SinkRisk.HIGH,
                            function_name=f"dict['{key_name}']",
                            file_path=file_path,
                            line_number=line_number,
                            code_snippet=snippet,
                            description=f"Secret placed in authentication field '{key_name}'",
                        ))

            if isinstance(value, ast.Call):
                _append_call_sink(value, tainted, sinks, file_path, lines)

        elif isinstance(value, ast.Call):
            _append_call_sink(value, tainted, sinks, file_path, lines)

    return sinks


def _append_call_sink(
    node: ast.Call,
    tainted: Set[str],
    sinks: List[ExposureSink],
    file_path: str,
    lines: List[str],
):
    if not any(_expr_contains_name(arg, tainted) for arg in node.args) and not any(
        kw.value is not None and _expr_contains_name(kw.value, tainted)
        for kw in node.keywords
    ):
        return

    func_name = _get_func_name(node.func)
    snippet = _line_snippet(lines, node.lineno)
    sink = classify_sink(func_name, snippet)
    if sink:
        sink.file_path = file_path
        sink.line_number = node.lineno
        _add_unique_sink(sinks, sink)


def classify_sink(func_name: str, code_context: str = "") -> Optional[ExposureSink]:
    """
    Classify a function call as an exposure sink.

    PRIORITY ORDER (function identity takes precedence over generic keywords):
    1. Known function-based sinks (network, log, file, database)
    2. Auth-related dictionary keys in code context

    Returns an ExposureSink if the function matches a known sink pattern,
    or None if it's not a recognized sink.
    """
    func_lower = func_name.lower()
    code_lower = code_context.lower()

    # ── PRIORITY 1: Function identity-based classification ────────────

    # Check network sinks FIRST (function name is the strongest signal)
    if _match_function_sink(func_name, NETWORK_SINKS):
        return ExposureSink(
            sink_type=ExposureType.NETWORK_REQUEST,
            risk_level=SinkRisk.HIGH,
            function_name=func_name,
            file_path="",
            line_number=0,
            code_snippet=code_context,
            description=f"Secret passed to network function '{func_name}' — may be transmitted externally",
        )

    # Check log/output sinks (function identity)
    if _match_function_sink(func_name, LOG_SINKS):
        return ExposureSink(
            sink_type=ExposureType.LOG_OUTPUT,
            risk_level=SinkRisk.LOW,
            function_name=func_name,
            file_path="",
            line_number=0,
            code_snippet=code_context,
            description=f"Secret potentially logged via '{func_name}'",
        )

    # Check file sinks (function identity)
    if _match_function_sink(func_name, FILE_SINKS):
        return ExposureSink(
            sink_type=ExposureType.FILE_WRITE,
            risk_level=SinkRisk.MEDIUM,
            function_name=func_name,
            file_path="",
            line_number=0,
            code_snippet=code_context,
            description=f"Secret potentially written to file via '{func_name}'",
        )

    # Check database sinks (function identity)
    if _match_function_sink(func_name, DB_SINKS):
        return ExposureSink(
            sink_type=ExposureType.DATABASE,
            risk_level=SinkRisk.MEDIUM,
            function_name=func_name,
            file_path="",
            line_number=0,
            code_snippet=code_context,
            description=f"Secret potentially stored in database via '{func_name}'",
        )

    # ── PRIORITY 2: Context-based classification ──────────────────────
    # Only apply generic keyword heuristics when function identity didn't match

    # Check for authorization header context in code context
    for auth_key in AUTH_DICT_KEYS:
        if auth_key in code_lower:
            return ExposureSink(
                sink_type=ExposureType.AUTH_HEADER,
                risk_level=SinkRisk.HIGH,
                function_name=func_name,
                file_path="",
                line_number=0,
                code_snippet=code_context,
                description=f"Secret used in authentication context ('{auth_key}')",
            )

    return None


def analyze_propagation_sinks(
    graph: PropagationGraph,
    file_path: str,
) -> List[ExposureSink]:
    """
    Analyze the terminal nodes of a propagation graph to identify
    exposure sinks.

    Args:
        graph: The propagation graph from the dataflow tracker
        file_path: Path to the source file

    Returns:
        List of identified exposure sinks
    """
    sinks: List[ExposureSink] = []

    for node in graph.nodes:
        # Check if this node represents a function call
        if node.operation in ("function_argument", "keyword_argument"):
            # Extract the function name from the node variable
            func_match = re.match(r'(\w+(?:\.\w+)*)\(', node.variable)
            if func_match:
                func_name = func_match.group(1)
                sink = classify_sink(func_name, node.code_snippet)
                if sink:
                    sink.file_path = file_path
                    sink.line_number = node.line_number
                    sinks.append(sink)

        # Check if this node is a dictionary value for auth-related keys
        if node.operation == "dict_value":
            key_match = re.search(r'\.(\w+)$', node.variable)
            if key_match:
                key_name = key_match.group(1).lower()
                if key_name in AUTH_DICT_KEYS:
                    sinks.append(ExposureSink(
                        sink_type=ExposureType.AUTH_HEADER,
                        risk_level=SinkRisk.HIGH,
                        function_name=node.variable,
                        file_path=file_path,
                        line_number=node.line_number,
                        code_snippet=node.code_snippet,
                        description=f"Secret assigned to authentication-related key '{key_name}'",
                    ))

    return sinks


def analyze_code_for_sinks(
    content: str,
    file_path: str,
    secret_variables: Set[str],
) -> List[ExposureSink]:
    """
    Directly analyze source code to find where secret variables are used
    as sink arguments. This supplements the propagation graph analysis.

    Identifies ALL applicable sinks — a single secret may have multiple
    exposure points (e.g., both in a header AND in a network request).
    """
    sinks: List[ExposureSink] = _analyze_python_code_for_sinks(
        content, file_path, secret_variables
    )
    lines = content.split('\n')

    for i, line in enumerate(lines):
        line_stripped = line.strip()

        for var in secret_variables:
            if var not in line:
                continue

            # Check for function calls containing the variable
            call_match = re.search(
                rf'(\w+(?:\.\w+)*)\s*\([^)]*\b{re.escape(var)}\b[^)]*\)',
                line
            )
            if call_match:
                func_name = call_match.group(1)
                sink = classify_sink(func_name, line_stripped)
                if sink:
                    sink.file_path = file_path
                    sink.line_number = i + 1
                    sinks.append(sink)

            # Check for auth-related dictionary assignments
            auth_match = re.search(
                rf'["\']([\w\-]+)["\']\s*:\s*\b{re.escape(var)}\b',
                line
            )
            if auth_match:
                key_name = auth_match.group(1).lower()
                if key_name in AUTH_DICT_KEYS:
                    sinks.append(ExposureSink(
                        sink_type=ExposureType.AUTH_HEADER,
                        risk_level=SinkRisk.HIGH,
                        function_name=f"dict['{key_name}']",
                        file_path=file_path,
                        line_number=i + 1,
                        code_snippet=line_stripped,
                        description=f"Secret '{var}' placed in authentication field '{key_name}'",
                    ))

    # Also check for function calls with tainted variables passed
    # indirectly (e.g. requests.get(url, headers=headers) where headers
    # contains a tainted variable assigned earlier).
    # Find variables that carry secret_variables values
    tainted_containers = set()
    for i, line in enumerate(lines):
        for var in secret_variables:
            # dict assignment: {"key": var}
            if re.search(rf'["\']([\w\-]+)["\']\s*:\s*\b{re.escape(var)}\b', line):
                # Find the dict variable on the left side of assignment
                dict_match = re.match(r'\s*(\w+)\s*=\s*\{', line)
                if dict_match:
                    tainted_containers.add(dict_match.group(1))

    # Now check if tainted containers are used in function calls
    for i, line in enumerate(lines):
        for container in tainted_containers:
            if container not in line:
                continue
            call_match = re.search(
                rf'(\w+(?:\.\w+)*)\s*\([^)]*\b{re.escape(container)}\b[^)]*\)',
                line
            )
            if call_match:
                func_name = call_match.group(1)
                sink = classify_sink(func_name, line.strip())
                if sink:
                    sink.file_path = file_path
                    sink.line_number = i + 1
                    # Check if we already have this type at this line
                    already_exists = any(
                        s.line_number == i + 1 and s.sink_type == sink.sink_type
                        for s in sinks
                    )
                    if not already_exists:
                        sinks.append(sink)

    # Deduplicate sinks by line number and type
    seen = set()
    unique_sinks = []
    for sink in sinks:
        key = (sink.line_number, sink.sink_type.value)
        if key not in seen:
            seen.add(key)
            unique_sinks.append(sink)

    return unique_sinks
