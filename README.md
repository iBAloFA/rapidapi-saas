# 🚀 Production-Grade DevSuite: Security, Metadata & SSL Trust API

[![RapidAPI Badge](https://shields.io)](https://rapidapi.com/sweettreats2threat-sweettreats2threat-default/api/phishing-url-threat-guard-exif-metadata-extractor)
[![Render Deployment](https://shields.io)](https://onrender.com)
[![License: MIT](https://shields.io)](https://opensource.org)

An enterprise-ready, high-performance, multi-service backend API utility suite built using Node.js and Express. This production engine handles network security scans, structural media parsing, and secure data logging under heavy loads. Deployed on Render with dual-pipeline fallbacks, the system guarantees low-latency tracking for microservices.

---

## ⚡ Core Engine Capabilities

*   🔍 **Phishing & Domain Threat Heuristics**: Analyzes target links using live asynchronous DNS resolution checks and structural keyword patterns.
*   📸 **Universal EXIF Extraction Pipeline**: Parses raw photographic image binary tables (JPEG, TIFF, HEIC) or dynamically falls back to vector metrics (SVG, PNG, GIF) without throwing server crashes.
*   🔒 **Automated SSL Certificate Validity Tracker**: Initiates background socket handshakes on port 443 to calculate certificate life spans and warn against critical expiration loops.
*   🛡️ **Gateway Proxy Security**: Protected with robust Helmet headers, CORS policies, global IP rate limits, and custom header proxy matching tokens.

---

## 🛠️ Marketplace API Integration Snippets

### 1. Real-Time Domain Threat Analyzer
**Endpoint Path**: `POST /api/v1/analyze-url`

```javascript
// JavaScript Fetch Example
const options = {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-RapidAPI-Key': 'YOUR_SUBSCRIBER_KEY_HERE',
    'X-RapidAPI-Host': '://rapidapi.com'
  },
  body: JSON.stringify({ url: 'http://secure-login-verify-bank.com' })
};

fetch('https://://rapidapi.com/api/v1/analyze-url', options)
  .then(res => res.json())
  .then(data => console.log(data));
```

#### Expected JSON Output Response
```json
{
  "url": "http://secure-login-verify-bank.com",
  "domain": "secure-login-verify-bank.com",
  "verdict": "Dangerous",
  "risk_score": 80,
  "metrics": {
    "domain_resolves": false,
    "highly_suspicious": true,
    "uses_raw_ip": false,
    "excessive_length": false
  }
}
```

---

### 2. High-Fidelity Image EXIF Metadata Extractor
**Endpoint Path**: `POST /api/v1/extract-metadata`

```python
# Python Requests Example
import requests

url = "https://://rapidapi.com/api/v1/extract-metadata"
payload = { "imageUrl": "https://githubusercontent.com" }
headers = {
    "Content-Type": "application/json",
    "X-RapidAPI-Key": "YOUR_SUBSCRIBER_KEY_HERE",
    "X-RapidAPI-Host": "://rapidapi.com"
}

response = requests.post(url, json=payload, headers=headers)
print(response.json())
```

#### Expected JSON Output Response
```json
{
  "status": "Success",
  "file_format": "JPEG",
  "file_size_bytes": 233505,
  "dimensions": { "width": 640, "height": 480 },
  "camera_metadata": {
    "make": "NIKON",
    "model": "COOLPIX P90",
    "software": "v1.0",
    "timestamp": "2008:11:01 21:15:00",
    "geolocation": { "lat": 43.4674, "lng": 11.8817 }
  }
}
```

---

### 3. Domain SSL Certificate Validity Checker
**Endpoint Path**: `POST /api/v1/check-ssl`

```bash
# cURL CLI Example
curl -X POST https://://rapidapi.com/api/v1/check-ssl \
  -H "Content-Type: application/json" \
  -H "X-RapidAPI-Key: YOUR_SUBSCRIBER_KEY_HERE" \
  -d '{"domain": "google.com"}'
```

#### Expected JSON Output Response
```json
{
  "domain": "google.com",
  "issuer": "Google Trust Services",
  "valid_from": "May 10 2026",
  "valid_to": "Aug 02 2026",
  "days_until_expiration": 50,
  "status": "Healthy"
}
```

---

## 📈 Active Marketplace Tiers

This suite operates on a multi-tier subscription setup to prevent cloud server flooding:
1. **Basic Tier** ($0.00) — 100 requests/month (Enforced Hard Limit protection).
2. **Pro Tier** ($9.00/mo) — 10,000 requests/month ($0.01 overage billing flexibility).
3. **Ultra Tier** ($29.00/mo) — 50,000 requests/month ($0.005 overage block capacity).

👉 **[Subscribe and grab your production credentials instantly on RapidAPI Marketplace Hub]
(https://rapidapi.com/sweettreats2threat-sweettreats2threat-default/api/phishing-url-threat-guard-exif-metadata-extractor)**
