// Vulnerable Sample: JavaScript Fragmented Secrets
// SYNTHETIC test data — ALL CREDENTIALS ARE FAKE

const axios = require('axios');

// ─── Test Case: Fragmented API Key in JavaScript ──────────────────────
const keyPart1 = "AIzaSy";
const keyPart2 = "DemoTe";
const keyPart3 = "stKey_JavaScript_12345678";

const googleApiKey = keyPart1 + keyPart2 + keyPart3;
// Should reconstruct: AIzaSyDemoTestKey_JavaScript_12345678

// ─── Test Case: Template literal construction ─────────────────────────
const tokenPrefix = "Bearer";
const tokenValue = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.SYNTHETIC.test";

const authHeader = `${tokenPrefix} ${tokenValue}`;

// ─── Test Case: Propagation to HTTP request ───────────────────────────
const config = {
    headers: {
        "Authorization": authHeader,
        "X-API-Key": googleApiKey
    }
};

axios.get("https://api.example.com/resource", config);

// ─── Test Case: Direct password assignment ────────────────────────────
const dbPassword = "SyntheticDBPassword_2024!";
const connectionString = `mongodb://admin:${dbPassword}@localhost:27017/testdb`;

// ─── Test Case: Console logging exposure ──────────────────────────────
console.log("API Key:", googleApiKey);
console.log("Connection:", connectionString);
