const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const dns = require('dns').promises;
const urlMod = require('url');
const exifr = require('exifr');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const SUSPICIOUS_KEYWORDS = ['verify', 'secure-login', 'bank', 'update-password', 'paypal', 'crypto-bonus'];

app.use(helmet());
app.use(cors());
app.use(express.json());

// RapidAPI Verification Middleware
const verifyRapidAPI = (req, res, next) => {
  const proxySecret = req.headers['x-rapidapi-proxy-secret'];
  if (!proxySecret || proxySecret !== process.env.RAPIDAPI_PROXY_SECRET) {
    return res.status(401).json({ error: "Unauthorized Gateway Proxy Request." });
  }
  next();
};
app.use(verifyRapidAPI);

// Clean Logging Middleware (No Database dependency)
const logUsage = (endpointName) => {
  return async (req, res, next) => {
    const start = Date.now();
    const rapidUserId = req.headers['x-rapidapi-user'] || 'local_developer';
    res.on('finish', () => {
      const duration = Date.now() - start;
      console.log(`[Log] /${endpointName} | User: ${rapidUserId} | Status: ${res.statusCode} | Time: ${duration}ms`);
    });
    next();
  };
};

// API Endpoint 1: Threat Analyzer
app.post('/api/v1/analyze-url', logUsage('analyze-url'), async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "Missing required 'url' parameter." });
    
    const parsedUrl = urlMod.parse(url);
    const hostname = parsedUrl.hostname;
    if (!hostname) return res.status(400).json({ error: "Invalid URL string formatting." });
    
    let domainExists = true;
    try { await dns.lookup(hostname); } catch { domainExists = false; }
    
    const hasSuspiciousKeywords = SUSPICIOUS_KEYWORDS.some(keyword => hostname.toLowerCase().includes(keyword));
    const isIpAddress = /^[0-9.]+$/.test(hostname);
    
    let riskScore = 0;
    if (!domainExists) riskScore += 50;
    if (hasSuspiciousKeywords) riskScore += 30;
    if (isIpAddress) riskScore += 20;
    
    return res.status(200).json({
      url,
      domain: hostname,
      verdict: riskScore >= 50 ? 'Dangerous' : riskScore >= 20 ? 'Suspicious' : 'Safe',
      risk_score: riskScore,
      metrics: { domain_resolves: domainExists, highly_suspicious: hasSuspiciousKeywords }
    });
  } catch (error) { 
    return res.status(500).json({ error: "Server structural processing error." }); 
  }
});

// API Endpoint 2: EXIF Metadata Extractor
app.post('/api/v1/extract-metadata', logUsage('extract-metadata'), async (req, res) => {
  try {
    const { imageUrl } = req.body;
    if (!imageUrl) return res.status(400).json({ error: "Missing required 'imageUrl' parameter." });
    
    const response = await fetch(imageUrl);
    if (!response.ok) return res.status(400).json({ error: "Failed to download image." });
    
    const buffer = await response.arrayBuffer();
    const metadata = await exifr.parse(buffer, { tiff: true, exif: true, gps: true });
    
    if (!metadata) return res.status(200).json({ status: "Success", message: "No EXIF data found.", metadata: null });
    
    return res.status(200).json({
      status: "Success",
      camera: { make: metadata.Make || "Unknown", model: metadata.Model || "Unknown" },
      timestamp: metadata.DateTimeOriginal || null,
      geolocation: metadata.latitude && metadata.longitude ? { lat: metadata.latitude, lng: metadata.longitude } : "Unavailable"
    });
  } catch (error) { 
    return res.status(500).json({ error: "Failed to process image: " + error.message }); 
  }
});

app.listen(PORT, () => console.log(`🚀 API Suite live and listening on port ${PORT}`));
