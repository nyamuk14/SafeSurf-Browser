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
    this.gsb_key = '';
    this.vt_key = '';
    this.gsb_api_url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
    this.vt_api_url = 'https://www.virustotal.com/vtapi/v2/url/report';
  }
  
  // Set API keys
  setApiKeys(gsb_key, vt_key) {
    this.gsb_key = gsb_key;
    this.vt_key = vt_key;
    console.log('Phishing detection API keys configured');
  }
  
  // Check URL against Google Safe Browsing
  async checkGoogleSafeBrowsing(url) {
    if (!this.gsb_key) {
      console.log('GSB API key not configured');
      return { isSafe: true, message: 'GSB check skipped - API key not configured' };
    }
    
    try {
      console.log('Checking URL with Google Safe Browsing...');
      
      const response = await axios.post(
        `${this.gsb_api_url}?key=${this.gsb_key}`,
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
            threatEntries: [{ url: url }]
          }
        }
      );

      const hasMatches = response.data && response.data.matches && response.data.matches.length > 0;
      console.log('GSB API Response:', JSON.stringify(response.data, null, 2));

      return {
        isSafe: !hasMatches,
        message: hasMatches ? `Threat detected by Google Safe Browsing: ${response.data.matches[0].threatType}` : 'No threats found by GSB'
      };
    } catch (error) {
      console.error('GSB API Error:', error.message);
      return {
        isSafe: false,
        message: 'Error checking Google Safe Browsing'
      };
    }
  }
  
  // Check URL against VirusTotal
  async checkVirusTotal(url) {
    if (!this.vt_key) {
      console.log('VirusTotal API key not configured');
      return { isSafe: true, message: 'VT check skipped - API key not configured' };
    }
    
    try {
      console.log('Checking URL with VirusTotal...');
      
      // Get the URL scan report
      const response = await axios.get(this.vt_api_url, {
        params: {
          apikey: this.vt_key,
          resource: url
        }
      });

      console.log('VT API Response:', JSON.stringify(response.data, null, 2));

      if (response.data.response_code === 0) {
        // URL not in VT database
        return {
          isSafe: true,
          message: 'URL not found in VirusTotal database'
        };
      }

      const positives = response.data.positives || 0;
      const total = response.data.total || 0;

      // Consider unsafe if any engine detected it as malicious
      const isSafe = positives === 0;
      
      return {
        isSafe,
        message: isSafe 
          ? 'No threats found by VirusTotal' 
          : `Threats detected by VirusTotal: ${positives}/${total} security vendors`
      };
    } catch (error) {
      console.error('VirusTotal API Error:', error.message);
      return {
        isSafe: false,
        message: 'Error checking VirusTotal'
      };
    }
  }
  
  // Main method to check a URL against all available sources
  async checkUrl(url) {
    console.log('Starting URL security check with:', {
      hasGSBKey: !!this.gsb_key,
      hasVTKey: !!this.vt_key,
      url: url
    });

    // Skip checks for Google search URLs
    if (url.includes('google.com/search')) {
      return { isSafe: true, message: 'Search query allowed' };
    }

    // Check cache first
    if (safeUrlCache.has(url)) {
      const cachedResult = safeUrlCache.get(url);
      if (Date.now() - cachedResult.timestamp < CACHE_DURATION) {
        console.log('Using cached result for:', url);
        return cachedResult.result;
      }
      safeUrlCache.delete(url);
    }
    
    try {
      // Run external API checks in parallel
      const [gsbCheck, vtCheck] = await Promise.all([
        this.checkGoogleSafeBrowsing(url),
        this.checkVirusTotal(url)
      ]);

      console.log('Security check results:', {
        gsb: gsbCheck,
        vt: vtCheck
      });

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

      const result = {
        isSafe: true,
        message: 'URL passed external security checks',
        details: {
          gsb: gsbCheck,
          vt: vtCheck
        }
      };

      // Cache the result
      safeUrlCache.set(url, {
        result,
        timestamp: Date.now()
      });

      return result;
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