const sizeOf = require('image-size'); // Add this line to the top of your server.js file

// --- UPGRADED ALL-FORMAT IMAGE METADATA PIPELINE ---
app.post('/api/v1/extract-metadata', logUsage('extract-metadata'), async (req, res) => {
  try {
    const { imageUrl } = req.body;
    if (!imageUrl) return res.status(400).json({ error: "Missing required 'imageUrl' parameter." });

    // 1. Safe stream fetch validation check
    const response = await fetch(imageUrl);
    if (!response.ok) return res.status(400).json({ error: "Failed to download image from the target URL." });

    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    const contentLength = response.headers.get('content-type') || '';

    // 2. High-Density Pipeline 1: Extract Binary EXIF Meta Profiles (JPEG, HEIC, TIFF)
    let exifData = null;
    try {
      exifData = await exifr.parse(buffer, { tiff: true, exif: true, gps: true });
    } catch (e) {
      // Quiet fallback mode if file doesn't support structured binary headers
      exifData = null;
    }

    // 3. High-Density Pipeline 2: Fallback Dimensional Heuristics (SVG, PNG, GIF)
    let layoutMetrics = { width: "Unknown", height: "Unknown", type: "Unknown" };
    try {
      const dimensions = sizeOf(buffer);
      layoutMetrics = {
        width: dimensions.width,
        height: dimensions.height,
        type: dimensions.type || contentLength.split('/')[1] || "Unknown"
      };
    } catch (e) {
      // Final fallback layer if image sizes cannot be structurally decoded
      if (imageUrl.toLowerCase().includes('.svg')) {
        layoutMetrics.type = 'svg';
      }
    }

    // 4. Unified Response Engine (Guarantees a 200 OK for ALL formats)
    return res.status(200).json({
      status: "Success",
      file_format: layoutMetrics.type.toUpperCase(),
      file_size_bytes: buffer.length,
      dimensions: {
        width: layoutMetrics.width,
        height: layoutMetrics.height
      },
      camera_metadata: exifData ? {
        make: exifData.Make || "Unknown",
        model: exifData.Model || "Unknown",
        software: exifData.Software || "Unknown",
        timestamp: exifData.DateTimeOriginal || null,
        geolocation: exifData.latitude && exifData.longitude ? { 
          lat: exifData.latitude, 
          lng: exifData.longitude 
        } : "Unavailable"
      } : "No embedded EXIF hardware profiles present in this file type format."
    });

  } catch (error) {
    return res.status(500).json({ error: "Failed to safely process target image structure: " + error.message });
  }
});
