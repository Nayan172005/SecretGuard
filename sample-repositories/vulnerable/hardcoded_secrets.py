# Vulnerable Sample: Direct hardcoded secrets
# SYNTHETIC test data — ALL CREDENTIALS ARE FAKE

import requests

# Direct API key
GOOGLE_API_KEY = "AIzaSyDirectHardcodedKey123456789ab"

# Direct AWS credentials
AWS_ACCESS_KEY = "AKIADIRECTTEST12345678"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYDEMO_SECRET"

# Database connection string
DATABASE_URL = "mongodb+srv://admin:DirectPassword123@cluster0.example.net/mydb"

# Hardcoded password
admin_password = "SuperSecretAdmin@2024!"

# GitHub token
GITHUB_TOKEN = "ghp_DirectTestTokenSynthetic1234567890ab"

# Stripe key
STRIPE_SECRET = "sk_live_SyntheticStripeKey1234567890"

# JWT token
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SYNTHETIC_SIGNATURE"

# Using credentials
headers = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "X-API-Key": GOOGLE_API_KEY
}

response = requests.post("https://api.example.com/data", headers=headers)
