const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const dns = require('dns').promises;
const urlMod = require('url');
const exifr = require('exifr');
const tls = require('tls');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security rules for phishing detection heuristics
const SUSPICIOUS_KEYWORDS = ['verify', 'secure-login', 'bank', 'update-password', 'paypal', 'crypto-bonus'];

// 1. Global Middleware Security Layers
app.use(helmet()); // Sets protective HTTP response headers
app.use(cors());   // Enables cross-origin sharing for your subscribers
app.use(express.json()); // Correctly parses JSON incoming payloads

// 2. Gateway Safety Net Rate Limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 Minute window
  max: 150, // Limits each individual IP footprint
  message: { error: "Rate limit exceeded. Please subscribe to a higher tier plan." }
});
app.use(globalLimiter);

// 3. Central Security Gateway Proxy Middleware Validation
const verifyRapidAPI = (req, res, next) => {
  const proxySecret = req.headers['x-rapidapi-proxy-secret'];
  
  if (!proxySecret || proxySecret !== process.env.RAPIDAPI_PROXY_SECRET) {
    return res.status(401).json({ 
      error: "Unauthorized Gateway Proxy Request. Access Denied." 
    });
  }
  next();
};

// Apply security gate enforcement rule to all downstream routes
app.use(verifyRapidAPI);

// 4. Local Performance Analytics Logger Middleware
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

// --- ENDPOINT 1: MICRO URL SECURITY & THREAT HEURISTICS ANALYZER ---
app.post('/api/v1/analyze-url', logUsage('analyze-url'), async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "Missing required 'url' parameter." });

    const parsedUrl = urlMod.parse(url);
    const hostname = parsedUrl.hostname;
    if (!hostname) return res.status(400).json({ error: "Invalid structural URL string formatting." });

    // Active Domain DNS Evaluation Check
    let domainExists = true;
    try { 
      await dns.lookup(hostname); 
    } catch { 
      domainExists = false; 
    }

    const hasSuspiciousKeywords = SUSPICIOUS_KEYWORDS.some(keyword => hostname.toLowerCase().includes(keyword));
    const isIpAddress = /^[0-9.]+$/.test(hostname);
    const unusualLength = hostname.length > 50;

    // Calculate structural threat matrix scoring indicators
    let riskScore = 0;
    if (!domainExists) riskScore += 50;
    if (hasSuspiciousKeywords) riskScore += 30;
    if (isIpAddress) riskScore += 20;
    if (unusualLength) riskScore += 10;

    return res.status(200).json({
      url,
      domain: hostname,
      verdict: riskScore >= 50 ? 'Dangerous' : riskScore >= 20 ? 'Suspicious' : 'Safe',
      risk_score: riskScore,
      metrics: {
        domain_resolves: domainExists,
        highly_suspicious: hasSuspiciousKeywords,
        uses_raw_ip: isIpAddress,
        excessive_length: unusualLength
      }
    });
  } catch (error) {
    return res.status(500).json({ error: "Server threat processing fallback layer error." });
  }
});

// --- ENDPOINT 2: HIGH-FIDELITY EXIF IMAGE METADATA EXTRACTOR ---
app.post('/api/v1/extract-metadata', logUsage('extract-metadata'), async (req, res) => {
  try {
    const { imageUrl } = req.body;
    if (!imageUrl) return res.status(400).json({ error: "Missing required 'imageUrl' parameter." });

    const response = await fetch(imageUrl);
    if (!response.ok) return res.status(400).json({ error: "Failed to fetch image stream from target source URL." });

    const buffer = await response.arrayBuffer();
    const metadata = await exifr.parse(buffer, { tiff: true, exif: true, gps: true });

    if (!metadata) {
      return res.status(200).json({ 
        status: "Success", 
        message: "No structural EXIF data profile markers discovered inside this image.", 
        metadata: null 
      });
    }

    return res.status(200).json({
      status: "Success",
      camera: {
        make: metadata.Make || "Unknown",
        model: metadata.Model || "Unknown"
      },
      software: metadata.Software || "Unknown",
      timestamp: metadata.DateTimeOriginal || null,
      geolocation: metadata.latitude && metadata.longitude ? {
        lat: metadata.latitude,
        lng: metadata.longitude
      } : "Unavailable"
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to process image payload parsing: " + error.message });
  }
});

// --- ENDPOINT 3: PREMIUM DOMAIN SSL VALIDITY & EXPIRATION CHECKER ---
app.post('/api/v1/check-ssl', logUsage('check-ssl'), async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: "Missing required 'domain' parameter." });

    // Clean up domain protocols if user passes full URL instead of raw domain
    let hostname = domain.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];

    // Establish handshakes connection profiling to extract signature blocks
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false // Prevents crash crashes on self-signed cert domains
    }, () => {
      const cert = socket.getPeerCertificate();
      socket.destroy();

      if (!cert || Object.keys(cert).length === 0) {
        return res.status(404).json({ error: "No active SSL/TLS handshake discovered on port 443." });
      }

      const validTo = new Date(cert.valid_to);
      const daysRemaining = Math.round((validTo - new Date()) / (1000 * 60 * 60 * 24));

      return res.status(200).json({
        domain: hostname,
        issuer: cert.issuer.O || "Unknown Certification Authority",
        valid_from: cert.valid_from,
        valid_to: cert.valid_to,
        days_until_expiration: daysRemaining,
        status: daysRemaining <= 0 ? "Expired" : daysRemaining <= 15 ? "Critical Risk Alert" : "Healthy"
      });
    });

    socket.on('error', (err) => {
      if (!res.headersSent) {
        return res.status(500).json({ error: "Handshake connection resolution failure: " + err.message });
      }
    });

  } catch (error) {
    return res.status(500).json({ error: "Server certificate evaluation validation pipeline error." });
  }
});

// Start active listener execution
app.listen(PORT, () => console.log(`🚀 API Suite live and listening on port ${PORT}`));
