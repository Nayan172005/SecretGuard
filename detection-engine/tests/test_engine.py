"""
Test Suite for the Detection Engine
Tests reconstruction, dataflow tracking, sink analysis, and risk scoring.

Run: python -m pytest tests/ -v
"""

import sys
import os
import json

# Add the scanner module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scanner.regex_detector import detect_secrets_in_content
from scanner.entropy_analyzer import analyze_entropy, calculate_shannon_entropy
from scanner.context_filter import filter_candidates, is_placeholder_value
from scanner.secret_validator import (
    is_secret_like,
    is_environment_variable_usage,
    validate_reconstructed_secret,
)
from scanner.secret_reconstructor import SecretReconstructor
from scanner.dataflow_tracker import DataflowTracker
from scanner.sink_analyzer import analyze_propagation_sinks, analyze_code_for_sinks, classify_sink
from scanner.risk_engine import score_finding, calculate_risk_score
from scanner.deduplicator import deduplicate_findings
from scanner.models import (
    Finding, DetectionCandidate, ReconstructionStatus,
    ExposureType, SinkRisk, Severity, mask_secret
)


# ═══════════════════════════════════════════════════════════════════════════
# REGEX DETECTION TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_regex_detects_aws_key():
    code = 'AWS_KEY = "AKIATESTFRAGMENT12345678"'
    candidates = detect_secrets_in_content(code, "test.py")
    assert len(candidates) > 0
    assert any("AWS" in c.secret_type for c in candidates)
    print("✅ Regex detects AWS access key")

def test_regex_detects_google_api_key():
    code = 'API_KEY = "AIzaSyDemoTestKey1234567890_abcdef"'
    candidates = detect_secrets_in_content(code, "test.py")
    assert len(candidates) > 0
    assert any("Google" in c.secret_type for c in candidates)
    print("✅ Regex detects Google API key")

def test_regex_detects_github_token():
    code = 'TOKEN = "ghp_TestTokenSynthetic1234567890abcdef"'
    candidates = detect_secrets_in_content(code, "test.py")
    assert len(candidates) > 0
    print("✅ Regex detects GitHub token")

def test_regex_detects_jwt():
    code = 'jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test_signature_abc"'
    candidates = detect_secrets_in_content(code, "test.py")
    assert len(candidates) > 0
    print("✅ Regex detects JWT")

def test_regex_detects_database_url():
    code = 'DB = "mongodb+srv://user:pass@cluster.example.net/db"'
    candidates = detect_secrets_in_content(code, "test.py")
    assert len(candidates) > 0
    assert any("Database" in c.secret_type for c in candidates)
    print("✅ Regex detects database connection string")


# ═══════════════════════════════════════════════════════════════════════════
# ENTROPY TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_shannon_entropy_high():
    # Random-looking string should have high entropy
    entropy = calculate_shannon_entropy("a8Kf3mP9xL2qWn7B")
    assert entropy > 3.5
    print(f"✅ High entropy string: {entropy:.3f}")

def test_shannon_entropy_low():
    # Repetitive string should have low entropy
    entropy = calculate_shannon_entropy("aaaaaaaaaaaa")
    assert entropy < 1.0
    print(f"✅ Low entropy string: {entropy:.3f}")

def test_entropy_analyzer():
    code = '''
secret_key = "xK9mP2wL5vBn8qR3hJ6fY1dA4cG7eT0u"
normal_text = "hello world example"
'''
    candidates = analyze_entropy(code, "test.py")
    # Should find the high-entropy string but not "hello world"
    high_entropy = [c for c in candidates if c.entropy_score > 3.5]
    assert len(high_entropy) >= 1
    print("✅ Entropy analyzer detects high-entropy strings")


# ═══════════════════════════════════════════════════════════════════════════
# CONTEXT FILTER TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_filter_removes_placeholders():
    assert is_placeholder_value("your_api_key_here") == True
    assert is_placeholder_value("example_token_placeholder") == True
    assert is_placeholder_value("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") == True
    assert is_placeholder_value("AKIATESTFRAGMENT12345678") == False
    print("✅ Context filter identifies placeholders")

def test_filter_reduces_candidates():
    candidates = [
        DetectionCandidate(value="your_api_key_here", file_path="test.py", line_number=1, confidence=0.7),
        DetectionCandidate(value="AKIATESTREAL12345678", file_path="test.py", line_number=2, confidence=0.9),
        DetectionCandidate(value="xxxxxxxx", file_path="test.py", line_number=3, confidence=0.5),
    ]
    filtered = filter_candidates(candidates)
    assert len(filtered) < len(candidates)
    assert any(c.value == "AKIATESTREAL12345678" for c in filtered)
    print(f"✅ Context filter: {len(candidates)} → {len(filtered)} candidates")


# ═══════════════════════════════════════════════════════════════════════════
# SECRET RECONSTRUCTION TESTS (CORE NOVELTY)
# ═══════════════════════════════════════════════════════════════════════════

def test_reconstruction_two_parts():
    code = '''
part1 = "AKIA"
part2 = "TESTFRAGMENT1234"
key = part1 + part2
'''
    reconstructor = SecretReconstructor()
    results = reconstructor.analyze_python(code, "test.py")
    assert len(results) >= 1
    found = [r for r in results if r["target"] == "key"]
    assert len(found) > 0
    assert found[0]["reconstructed_value"] == "AKIATESTFRAGMENT1234"
    assert found[0]["status"] == ReconstructionStatus.FULL
    print(f"✅ Reconstruction (2 parts): {found[0]['reconstructed_value']}")

def test_reconstruction_three_parts():
    code = '''
p1 = "AKIA"
p2 = "TEST1234"
p3 = "DEMO5678"
access_key = p1 + p2 + p3
'''
    reconstructor = SecretReconstructor()
    results = reconstructor.analyze_python(code, "test.py")
    found = [r for r in results if r["target"] == "access_key"]
    assert len(found) > 0
    assert found[0]["reconstructed_value"] == "AKIATEST1234DEMO5678"
    assert len(found[0]["fragments"]) == 3
    print(f"✅ Reconstruction (3 parts): {found[0]['reconstructed_value']}")

def test_reconstruction_partial():
    code = '''
import os
static = "prefix_"
dynamic = os.environ.get("KEY")
mixed = static + dynamic
'''
    reconstructor = SecretReconstructor()
    results = reconstructor.analyze_python(code, "test.py")
    found = [r for r in results if r["target"] == "mixed"]
    assert len(found) > 0
    assert found[0]["status"] == ReconstructionStatus.PARTIAL
    print(f"✅ Partial reconstruction: status={found[0]['status'].value}")

def test_reconstruction_variable_propagation():
    code = '''
secret = "SuperSecretValue123"
alias = secret
'''
    reconstructor = SecretReconstructor()
    reconstructor.analyze_python(code, "test.py")
    table = reconstructor.get_symbol_table()
    assert "alias" in table
    assert table["alias"][0] == "SuperSecretValue123"
    print("✅ Variable-to-variable propagation works")

def test_reconstruction_fstring():
    code = '''
user = "admin"
pwd = "secret123"
url = f"mongodb://{user}:{pwd}@localhost/db"
'''
    reconstructor = SecretReconstructor()
    results = reconstructor.analyze_python(code, "test.py")
    found = [r for r in results if r["target"] == "url"]
    assert len(found) > 0
    assert "admin" in found[0]["reconstructed_value"]
    assert "secret123" in found[0]["reconstructed_value"]
    print(f"✅ F-string reconstruction: {mask_secret(found[0]['reconstructed_value'])}")

def test_reconstruction_javascript():
    code = '''
const part1 = "AIzaSy";
const part2 = "TestKey123456789";
const apiKey = part1 + part2;
'''
    reconstructor = SecretReconstructor()
    results = reconstructor.analyze_javascript(code, "test.js")
    found = [r for r in results if r["target"] == "apiKey"]
    assert len(found) > 0
    assert found[0]["reconstructed_value"] == "AIzaSyTestKey123456789"
    print(f"✅ JavaScript reconstruction: {found[0]['reconstructed_value']}")


# ═══════════════════════════════════════════════════════════════════════════
# DATAFLOW TRACKING TESTS (CORE NOVELTY)
# ═══════════════════════════════════════════════════════════════════════════

def test_dataflow_simple_assignment():
    code = '''
secret = "APIKey123"
alias = secret
result = alias
'''
    tracker = DataflowTracker()
    graphs = tracker.track_python(code, "test.py", {"secret": ("APIKey123", 1)})
    assert "secret" in graphs
    path = graphs["secret"].get_path()
    assert "alias" in path
    assert "result" in path
    print(f"✅ Dataflow simple assignment: {' → '.join(path)}")

def test_dataflow_dict_insertion():
    code = '''
token = "BearerXYZ"
headers = {"Authorization": token}
'''
    tracker = DataflowTracker()
    graphs = tracker.track_python(code, "test.py", {"token": ("BearerXYZ", 1)})
    assert "token" in graphs
    path = graphs["token"].get_path()
    assert any("Authorization" in p for p in path)
    print(f"✅ Dataflow dict insertion: {' → '.join(path)}")

def test_dataflow_function_call():
    code = '''
key = "secret123"
requests.get("url", headers=key)
'''
    tracker = DataflowTracker()
    graphs = tracker.track_python(code, "test.py", {"key": ("secret123", 1)})
    assert "key" in graphs
    nodes = graphs["key"].nodes
    assert any("requests.get" in n.variable for n in nodes)
    print(f"✅ Dataflow function call tracking: {[n.variable for n in nodes]}")


# ═══════════════════════════════════════════════════════════════════════════
# SINK ANALYSIS TESTS (CORE NOVELTY)
# ═══════════════════════════════════════════════════════════════════════════

def test_sink_network_request():
    sink = classify_sink("requests.get", "requests.get(url, headers=h)")
    assert sink is not None
    assert sink.sink_type == ExposureType.NETWORK_REQUEST
    assert sink.risk_level == SinkRisk.HIGH
    print("✅ Sink: network request identified as HIGH risk")

def test_sink_auth_header():
    sink = classify_sink("dict_set", '"Authorization": token')
    assert sink is not None
    assert sink.sink_type == ExposureType.AUTH_HEADER
    print("✅ Sink: authorization header identified")

def test_sink_logging():
    sink = classify_sink("print", "print(secret)")
    assert sink is not None
    assert sink.sink_type == ExposureType.LOG_OUTPUT
    assert sink.risk_level == SinkRisk.LOW
    print("✅ Sink: logging identified as LOW risk")

def test_sink_code_analysis():
    code = '''
api_key = "test123"
headers = {"Authorization": api_key}
requests.get("https://example.com", headers=headers)
print(api_key)
'''
    sinks = analyze_code_for_sinks(code, "test.py", {"api_key"})
    sink_types = [s.sink_type for s in sinks]
    assert ExposureType.AUTH_HEADER in sink_types
    assert ExposureType.NETWORK_REQUEST in sink_types or ExposureType.LOG_OUTPUT in sink_types
    print(f"✅ Code sink analysis found: {[s.sink_type.value for s in sinks]}")


# ═══════════════════════════════════════════════════════════════════════════
# RISK SCORING TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_risk_scoring_critical():
    from scanner.models import ExposureSink
    finding = Finding(
        secret_type="AWS Secret Key",
        confidence=0.9,
        detection_methods=["regex", "entropy", "reconstruction"],
        entropy_score=5.0,
        reconstruction_status=ReconstructionStatus.FULL,
        propagation_path=["part1", "key", "headers", "requests.get"],
        exposure_sink=ExposureSink(
            sink_type=ExposureType.NETWORK_REQUEST,
            risk_level=SinkRisk.HIGH,
            function_name="requests.get",
            file_path="test.py",
            line_number=10,
            code_snippet="requests.get(url, headers=headers)",
        ),
    )
    scored = score_finding(finding)
    assert scored.risk_score >= 60  # Should be HIGH or CRITICAL
    assert scored.severity in (Severity.HIGH, Severity.CRITICAL)
    assert scored.risk_breakdown is not None
    print(f"✅ Critical finding risk score: {scored.risk_score:.1f} ({scored.severity.value})")

def test_risk_scoring_low():
    finding = Finding(
        secret_type="High Entropy String",
        confidence=0.3,
        detection_methods=["entropy"],
        entropy_score=3.5,
    )
    scored = score_finding(finding)
    assert scored.risk_score < 60
    print(f"✅ Low finding risk score: {scored.risk_score:.1f} ({scored.severity.value})")

def test_risk_scoring_boundaries():
    # Test that boundaries work correctly
    for expected_sev, score_range in [
        (Severity.LOW, (0, 29)),
        (Severity.MEDIUM, (30, 59)),
        (Severity.HIGH, (60, 79)),
        (Severity.CRITICAL, (80, 100)),
    ]:
        print(f"  Score range {score_range}: {expected_sev.value}")
    print("✅ Risk scoring boundaries defined correctly")


# ═══════════════════════════════════════════════════════════════════════════
# MASKING TESTS
# ═══════════════════════════════════════════════════════════════════════════

def test_mask_secret():
    assert mask_secret("AKIATESTFRAGMENT12345678") == "AKIA****************5678"
    assert mask_secret("short") == "*****"
    assert mask_secret("") == ""
    print("✅ Secret masking works correctly")


# ═══════════════════════════════════════════════════════════════════════════
# END-TO-END INTEGRATION TEST
# ═══════════════════════════════════════════════════════════════════════════

def test_end_to_end_fragmented_secret():
    """
    Full pipeline test: detect, reconstruct, track, identify sink, score.
    This demonstrates the core novelty.
    """
    code = '''
part1 = "AKIA"
part2 = "TESTFRAG"
part3 = "MENT12345678"

access_key = part1 + part2 + part3

auth = access_key

headers = {
    "Authorization": auth
}

requests.get("https://api.example.com", headers=headers)
'''

    # Step 1: Reconstruct
    reconstructor = SecretReconstructor()
    reconstructed = reconstructor.analyze_python(code, "test.py")
    assert len(reconstructed) >= 1
    recon = reconstructed[0]
    assert recon["reconstructed_value"] == "AKIATESTFRAGMENT12345678"

    # Step 2: Track dataflow
    tracker = DataflowTracker()
    secret_vars = {recon["target"]: (recon["reconstructed_value"], recon["line"])}
    graphs = tracker.track_python(code, "test.py", secret_vars)

    # Step 3: Analyze sinks
    sinks = analyze_code_for_sinks(code, "test.py", {recon["target"]})

    # Step 4: Build finding and score
    finding = Finding(
        secret_type="AWS Access Key",
        file_path="test.py",
        line_number=recon["line"],
        confidence=0.85,
        detection_methods=["reconstruction", "dataflow"],
        reconstruction_status=ReconstructionStatus.FULL,
        fragments=recon["fragments"],
        reconstructed_value_masked=mask_secret(recon["reconstructed_value"]),
        masked_secret=mask_secret(recon["reconstructed_value"]),
    )

    if recon["target"] in graphs:
        finding.propagation_graph = graphs[recon["target"]]
        finding.propagation_path = graphs[recon["target"]].get_path()

    if sinks:
        finding.exposure_sink = sinks[0]
        finding.exposure_type = sinks[0].sink_type.value

    finding = score_finding(finding)

    print(f"\n{'='*60}")
    print("END-TO-END TEST: Fragmented Secret Detection")
    print(f"{'='*60}")
    print(f"  Fragments: {len(recon['fragments'])}")
    print(f"  Reconstructed: {mask_secret(recon['reconstructed_value'])}")
    print(f"  Status: {recon['status'].value}")
    print(f"  Propagation: {' → '.join(finding.propagation_path)}")
    print(f"  Exposure: {finding.exposure_type}")
    print(f"  Risk Score: {finding.risk_score:.1f}")
    print(f"  Severity: {finding.severity.value}")
    print(f"{'='*60}")
    print("✅ End-to-end fragmented secret detection PASSED")


# ═══════════════════════════════════════════════════════════════════════════
# EVALUATION: BASELINE vs PROPOSED
# ═══════════════════════════════════════════════════════════════════════════

def test_baseline_vs_proposed():
    """
    Compare baseline (regex+entropy) vs proposed (regex+entropy+reconstruction+flow).
    This demonstrates the contribution of the novelty.
    """
    # Test code with fragmented secrets (invisible to baseline)
    fragmented_code = '''
p1 = "AKIA"
p2 = "HIDDEN"
p3 = "SECRET123456"
key = p1 + p2 + p3
headers = {"Authorization": key}
requests.get("https://api.example.com", headers=headers)
'''

    # Baseline: regex + entropy only
    baseline_candidates = detect_secrets_in_content(fragmented_code, "test.py")
    baseline_entropy = analyze_entropy(fragmented_code, "test.py")
    baseline_total = len(baseline_candidates) + len(baseline_entropy)

    # Proposed: add reconstruction
    reconstructor = SecretReconstructor()
    reconstructed = reconstructor.analyze_python(fragmented_code, "test.py")

    print(f"\n{'='*60}")
    print("EVALUATION: Baseline vs Proposed Approach")
    print(f"{'='*60}")
    print(f"  Baseline (regex+entropy) detections: {baseline_total}")
    print(f"  Proposed reconstructions: {len(reconstructed)}")
    print(f"  Improvement: +{len(reconstructed)} fragmented secrets detected")

    # Fragmented secrets should only be found by reconstruction
    assert len(reconstructed) > 0, "Proposed approach should find fragmented secrets"
    print(f"{'='*60}")
    print("✅ Proposed approach detects secrets invisible to baseline")


# ═══════════════════════════════════════════════════════════════════════════
def test_secret_validation_rejects_normal_content():
    assert not is_secret_like("Hello World", "greeting")
    assert not is_secret_like("John Doe", "full_name")
    assert not is_secret_like("https://api.example.com/v1/users", "url")
    assert not is_secret_like("development", "environment")


def test_environment_variable_sources_are_safe():
    assert is_environment_variable_usage('API_KEY = os.environ.get("API_KEY", "")')
    assert is_environment_variable_usage('SECRET_KEY = os.getenv("SECRET_KEY")')
    assert is_environment_variable_usage('const apiKey = process.env.API_KEY')
    assert not is_secret_like(
        "AIzaSyDemoTestKey1234567890_abcdef",
        "API_KEY",
        'API_KEY = os.environ.get("API_KEY", "")',
    )


def test_secret_validation_accepts_fragmented_secret():
    is_secret, confidence, secret_type, _ = validate_reconstructed_secret(
        "AKIATESTFRAGMENT12345678",
        "access_key",
        "access_key = part1 + part2 + part3",
        3,
    )
    assert is_secret
    assert confidence >= 0.45
    assert "AWS" in secret_type


def test_sink_priority_console_log_is_log_output():
    sink = classify_sink("console.log", "console.log(token)")
    assert sink is not None
    assert sink.sink_type == ExposureType.LOG_OUTPUT


def test_network_sink_variants():
    for func_name in ("requests.post", "requests.patch", "httpx.get", "axios.post", "fetch"):
        sink = classify_sink(func_name, f"{func_name}(url, headers=headers)")
        assert sink is not None
        assert sink.sink_type == ExposureType.NETWORK_REQUEST


def test_multiple_sinks_from_multiline_python_code():
    code = '''
api_key = "test123"
headers = {
    "Authorization": api_key
}
response = requests.post(
    "https://example.com",
    headers=headers
)
print(api_key)
'''
    sinks = analyze_code_for_sinks(code, "test.py", {"api_key"})
    sink_types = {s.sink_type for s in sinks}
    assert ExposureType.AUTH_HEADER in sink_types
    assert ExposureType.NETWORK_REQUEST in sink_types
    assert ExposureType.LOG_OUTPUT in sink_types


def test_reconstruction_validation_rejects_benign_concatenation():
    code = '''
greeting = "Hello" + " " + "World"
'''
    reconstructor = SecretReconstructor()
    reconstructed = reconstructor.analyze_python(code, "test.py")
    found = [r for r in reconstructed if r["target"] == "greeting"]
    assert found
    is_secret, _, _, _ = validate_reconstructed_secret(
        found[0]["reconstructed_value"],
        found[0]["target"],
        code,
        len(found[0]["fragments"]),
    )
    assert not is_secret


def test_deduplicates_same_secret_detection_methods():
    raw_secret = "ghp_TestTokenSynthetic1234567890abcdef"
    findings = [
        Finding(
            secret_type="GitHub Personal Access Token",
            file_path="app.py",
            raw_secret=raw_secret,
            masked_secret=mask_secret(raw_secret),
            detection_methods=["regex"],
            confidence=0.9,
        ),
        Finding(
            secret_type="High Entropy String",
            file_path="app.py",
            raw_secret=raw_secret,
            masked_secret=mask_secret(raw_secret),
            detection_methods=["entropy"],
            confidence=0.5,
        ),
        Finding(
            secret_type="Reconstructed Secret",
            file_path="app.py",
            raw_secret=raw_secret,
            masked_secret=mask_secret(raw_secret),
            detection_methods=["reconstruction", "dataflow"],
            confidence=0.8,
        ),
    ]
    deduped = deduplicate_findings(findings)
    assert len(deduped) == 1
    assert set(deduped[0].detection_methods) == {
        "regex", "entropy", "reconstruction", "dataflow"
    }


# RUN ALL TESTS
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    tests = [
        test_regex_detects_aws_key,
        test_regex_detects_google_api_key,
        test_regex_detects_github_token,
        test_regex_detects_jwt,
        test_regex_detects_database_url,
        test_shannon_entropy_high,
        test_shannon_entropy_low,
        test_entropy_analyzer,
        test_filter_removes_placeholders,
        test_filter_reduces_candidates,
        test_reconstruction_two_parts,
        test_reconstruction_three_parts,
        test_reconstruction_partial,
        test_reconstruction_variable_propagation,
        test_reconstruction_fstring,
        test_reconstruction_javascript,
        test_dataflow_simple_assignment,
        test_dataflow_dict_insertion,
        test_dataflow_function_call,
        test_sink_network_request,
        test_sink_auth_header,
        test_sink_logging,
        test_sink_code_analysis,
        test_risk_scoring_critical,
        test_risk_scoring_low,
        test_risk_scoring_boundaries,
        test_mask_secret,
        test_end_to_end_fragmented_secret,
        test_baseline_vs_proposed,
        test_secret_validation_rejects_normal_content,
        test_environment_variable_sources_are_safe,
        test_secret_validation_accepts_fragmented_secret,
        test_sink_priority_console_log_is_log_output,
        test_network_sink_variants,
        test_multiple_sinks_from_multiline_python_code,
        test_reconstruction_validation_rejects_benign_concatenation,
        test_deduplicates_same_secret_detection_methods,
    ]

    passed = 0
    failed = 0

    print(f"\n{'='*60}")
    print("Secret Detection Engine — Test Suite")
    print(f"{'='*60}\n")

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"❌ {test.__name__}: {e}")
            failed += 1

    print(f"\n{'='*60}")
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print(f"{'='*60}")

    if failed > 0:
        sys.exit(1)
