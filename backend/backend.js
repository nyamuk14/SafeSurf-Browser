const express = require('express');
const axios = require('axios');
require('dotenv').config();
const helmet = require('helmet');

const DownloadSecurity = require('./security/download-security');
const urlhausChecker = new DownloadSecurity();

const app = express();
app.use(express.json());
app.use(helmet());

// On backend startup, fetch URLhaus database
(async () => {
  await urlhausChecker.updateUrlHausDatabase();
})();

// POST /check-url: expects { url: 'https://example.com' }
app.post('/check-url', async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'Missing url in request body' });
  }

  // Prepare API keys
  const VT_KEY = process.env.VIRUS_TOTAL_API_KEY;
  const GSB_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  // Prepare results
  let vtResult = null;
  let gsbResult = null;
  let vtError = null;
  let gsbError = null;

  // VirusTotal check
  try {
    const vtResponse = await axios.get('https://www.virustotal.com/vtapi/v2/url/report', {
      params: {
        apikey: VT_KEY,
        resource: url
      }
    });
    vtResult = vtResponse.data;
  } catch (err) {
    vtError = err.message || 'VirusTotal check failed';
  }

  // Google Safe Browsing check
  try {
    const gsbResponse = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GSB_KEY}`,
      {
        client: {
          clientId: 'SafeSurf Browser',
          clientVersion: '1.0.0'
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION'
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      }
    );
    gsbResult = gsbResponse.data;
  } catch (err) {
    gsbError = err.message || 'Google Safe Browsing check failed';
  }

  res.json({
    vt: vtResult,
    vtError,
    gsb: gsbResult,
    gsbError
  });
});

// POST /check-urlhaus: expects { url: 'https://example.com' }
app.post('/check-urlhaus', async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: 'Missing url in request body' });
  }
  const result = await urlhausChecker.checkDownloadUrl(url);
  res.json(result);
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
}); 