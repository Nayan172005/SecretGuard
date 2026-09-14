"""
Exposure Sink Analyzer — CORE NOVELTY MODULE

Identifies where reconstructed and tracked secrets eventually reach.
Classifies sinks by type (network, auth, file, logging, database)
and risk level (HIGH, MEDIUM, LOW).

This module examines the propagation graph's terminal nodes and
the surrounding code to determine the exposure mechanism.
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
    "urllib.request.urlopen", "urlopen",
    # Python httpx
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
    "httpx.AsyncClient", "httpx.Client",
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


def classify_sink(func_name: str, code_context: str = "") -> Optional[ExposureSink]:
    """
    Classify a function call as an exposure sink.

    Returns an ExposureSink if the function matches a known sink pattern,
    or None if it's not a recognized sink.
    """
    func_lower = func_name.lower()
    code_lower = code_context.lower()

    # Check network sinks
    for sink in NETWORK_SINKS:
        if sink.lower() in func_lower or func_lower.endswith(sink.lower().split('.')[-1]):
            return ExposureSink(
                sink_type=ExposureType.NETWORK_REQUEST,
                risk_level=SinkRisk.HIGH,
                function_name=func_name,
                file_path="",
                line_number=0,
                code_snippet=code_context,
                description=f"Secret passed to network function '{func_name}' — may be transmitted externally",
            )

    # Check for authorization header context
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

    # Check log/output sinks
    for sink in LOG_SINKS:
        if sink.lower() in func_lower:
            return ExposureSink(
                sink_type=ExposureType.LOG_OUTPUT,
                risk_level=SinkRisk.LOW,
                function_name=func_name,
                file_path="",
                line_number=0,
                code_snippet=code_context,
                description=f"Secret potentially logged via '{func_name}'",
            )

    # Check file sinks
    for sink in FILE_SINKS:
        if sink.lower() in func_lower:
            return ExposureSink(
                sink_type=ExposureType.FILE_WRITE,
                risk_level=SinkRisk.MEDIUM,
                function_name=func_name,
                file_path="",
                line_number=0,
                code_snippet=code_context,
                description=f"Secret potentially written to file via '{func_name}'",
            )

    # Check database sinks
    for sink in DB_SINKS:
        if sink.lower() in func_lower:
            return ExposureSink(
                sink_type=ExposureType.DATABASE,
                risk_level=SinkRisk.MEDIUM,
                function_name=func_name,
                file_path="",
                line_number=0,
                code_snippet=code_context,
                description=f"Secret potentially stored in database via '{func_name}'",
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
    """
    sinks: List[ExposureSink] = []
    lines = content.split('\n')

    all_sink_patterns = set()
    all_sink_patterns.update(s.lower() for s in NETWORK_SINKS)
    all_sink_patterns.update(s.lower() for s in LOG_SINKS)
    all_sink_patterns.update(s.lower() for s in FILE_SINKS)
    all_sink_patterns.update(s.lower() for s in DB_SINKS)

    for i, line in enumerate(lines):
        line_lower = line.lower().strip()

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
                sink = classify_sink(func_name, line.strip())
                if sink:
                    sink.file_path = file_path
                    sink.line_number = i + 1
                    sinks.append(sink)

            # Check for auth-related dictionary assignments
            auth_match = re.search(
                rf'["\'](\w+)["\']\s*:\s*\b{re.escape(var)}\b',
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
                        code_snippet=line.strip(),
                        description=f"Secret '{var}' placed in authentication field '{key_name}'",
                    ))

    # Deduplicate sinks by line number and type
    seen = set()
    unique_sinks = []
    for sink in sinks:
        key = (sink.line_number, sink.sink_type.value)
        if key not in seen:
            seen.add(key)
            unique_sinks.append(sink)

    return unique_sinks
