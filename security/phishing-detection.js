const axios = require('axios');
const { URL } = require('url');

// Store for caching previous phishing check results to reduce API calls
const safeUrlCache = new Map();
const CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

// List of keywords often associated with phishing
const PHISHING_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'account', 'password',
  'secure', 'update', 'banking', 'payment', 'confirm',
  'alert', 'suspended', 'verify'
];

class PhishingDetection {
  constructor() {
    this.backend_url = 'http://localhost:3001/check-url';
  }
  
  // Set API keys (no longer needed, but kept for compatibility)
  setApiKeys(gsb_key, vt_key) {
    // No-op: API keys are now handled by the backend
    console.log('Phishing detection API keys are now managed by the backend.');
  }
  
  // Check URL against Google Safe Browsing and VirusTotal via backend
  async checkUrl(url) {
    try {
      const response = await axios.post(this.backend_url, { url });
      const { vt, gsb } = response.data;

      // Process Google Safe Browsing result
      let gsbCheck = { isSafe: true, message: 'No threats found by GSB' };
      if (gsb && gsb.matches && gsb.matches.length > 0) {
        gsbCheck = {
          isSafe: false,
          message: `Threat detected by Google Safe Browsing: ${gsb.matches[0].threatType}`
        };
      }

      // Process VirusTotal result
      let vtCheck = { isSafe: true, message: 'No threats found by VirusTotal' };
      if (vt && vt.response_code === 0) {
        vtCheck = {
          isSafe: true,
          message: 'URL not found in VirusTotal database'
        };
      } else if (vt && vt.positives > 0) {
        vtCheck = {
          isSafe: false,
          message: `Threats detected by VirusTotal: ${vt.positives}/${vt.total} security vendors`
        };
      }

      // Only consider the external API results
      if (!gsbCheck.isSafe || !vtCheck.isSafe) {
        const messages = [
          !gsbCheck.isSafe ? gsbCheck.message : null,
          !vtCheck.isSafe ? vtCheck.message : null
        ].filter(msg => msg !== null);

        return {
          isSafe: false,
          message: messages.join('; ')
        };
      }

      return {
        isSafe: true,
        message: 'URL passed external security checks',
        details: {
          gsb: gsbCheck,
          vt: vtCheck
        }
      };
    } catch (error) {
      console.error('Error during security checks:', error);
      return {
        isSafe: false,
        message: `Security check error: ${error.message}`,
        error: true
      };
    }
  }
}

module.exports = new PhishingDetection(); 