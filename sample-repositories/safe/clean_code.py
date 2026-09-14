# Safe Sample: Clean code with no real secrets
# This file should produce ZERO or very few findings

import os
import requests

# Configuration loaded from environment variables (SAFE)
API_KEY = os.environ.get("API_KEY", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "")

# Placeholder values (should be filtered as false positives)
EXAMPLE_KEY = "your_api_key_here"
DEMO_TOKEN = "example_token_placeholder"
TEST_SECRET = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Documentation example (should be filtered)
# Example: api_key = "AIzaSyYourKeyHere"
# Example: token = "ghp_YourTokenHere"

# Safe string operations (not secrets)
greeting = "Hello" + " " + "World"
full_name = "John" + " " + "Doe"
url = "https://api.example.com" + "/v1" + "/users"

# Normal code
def get_user_data(user_id):
    """Fetch user data from the API."""
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    response = requests.get(f"{url}/{user_id}", headers=headers)
    return response.json()

# Configuration class
class Config:
    DEBUG = True
    TESTING = False
    LOG_LEVEL = "INFO"
    MAX_RETRIES = 3
    TIMEOUT = 30

# Normal computation
def calculate_checksum(data):
    result = 0
    for byte in data:
        result = (result + byte) % 256
    return hex(result)
