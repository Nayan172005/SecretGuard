# Vulnerable Sample: Fragmented Secret Construction
# This file contains SYNTHETIC test data for demonstrating
# Program-Flow-Aware Secret Reconstruction and Exposure Analysis
# ALL CREDENTIALS ARE FAKE AND FOR TESTING ONLY

import requests

# ─── Test Case 1: Fragmented AWS Access Key ──────────────────────────────
# The access key is split across 3 variables and concatenated
part1 = "AKIA"
part2 = "TESTFRAG"
part3 = "MENT12345678"

access_key = part1 + part2 + part3

# This should be reconstructed as: AKIATESTFRAGMENT12345678

# ─── Test Case 2: Fragmented Secret with Propagation ────────────────────
# The secret propagates through multiple variables before reaching a sink
secret_prefix = "ghp_"
secret_body = "SyntheticTestToken1234567890abcdef"

github_token = secret_prefix + secret_body

auth_value = github_token
auth_header = "Bearer " + auth_value

headers = {
    "Authorization": auth_header,
    "Content-Type": "application/json"
}

# This is the EXPOSURE SINK — the secret reaches an external HTTP request
response = requests.get("https://api.example.com/data", headers=headers)

# ─── Test Case 3: Direct API Key (for comparison) ──────────────────────
API_KEY = "AIzaSyDemoTestKey1234567890_abcdef"

# ─── Test Case 4: Secret printed to logs ─────────────────────────────────
debug_token = "sk_live_DEMO_test_token_1234567890ab"
print(f"Debug: Using token {debug_token}")

# ─── Test Case 5: Multi-step reconstruction with format string ──────────
db_host = "mongodb+srv"
db_user = "admin"
db_pass = "SyntheticP@ss123"
db_cluster = "cluster0.example.net"
db_name = "production"

connection_string = f"{db_host}://{db_user}:{db_pass}@{db_cluster}/{db_name}"
# Should reconstruct: mongodb+srv://admin:SyntheticP@ss123@cluster0.example.net/production

# ─── Test Case 6: Partially resolvable secret ───────────────────────────
import os
static_part = "prefix_SYNTHETIC_"
dynamic_part = os.environ.get("SECRET_SUFFIX", "")

# This should be marked as PARTIAL reconstruction
mixed_key = static_part + dynamic_part

# ─── Test Case 7: Base64 encoded secret ─────────────────────────────────
import base64
encoded_secret = "U3ludGhldGljU2VjcmV0VGVzdDEyMw=="  # "SyntheticSecretTest123"
decoded_secret = base64.b64decode(encoded_secret).decode()
