const axios = require('axios');

// Store for caching URL checks to avoid repeated lookups
const urlCache = new Map();
const CACHE_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

class DownloadSecurity {
  constructor() {
    this.urlHausLastUpdate = 0;
    this.maliciousUrls = new Map();
    this.urlHausData = null;
    this.loadUrlHausDatabase();
  }

  // Download URLhaus database - updated to use JSON format
  async updateUrlHausDatabase() {
    // Don't update more than once per day
    const now = Date.now();
    if (now - this.urlHausLastUpdate < 24 * 60 * 60 * 1000) {
      return;
    }

    try {
      // Download the URLhaus JSON database instead of CSV
      console.log('[Security] Downloading URLhaus JSON database...');

      // Add a timeout to the request to prevent hanging
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

      const response = await axios.get('https://urlhaus.abuse.ch/downloads/json_online/', {
        timeout: 5000,
        signal: controller.signal
      }).finally(() => clearTimeout(timeoutId));

      // Check if we actually got data back
      if (!response.data) {
        console.log('[Security] No data received from URLhaus, using existing database if available');
        return false;
      }

      // Store the data in memory
      this.urlHausData = response.data;

      // Update last update timestamp
      this.urlHausLastUpdate = now;

      // Load the database
      this.loadUrlHausDatabase();

      return true;
    } catch (error) {
      console.error('Error updating URLhaus database:', error.message || error);
      return false;
    }
  }

  // Load the URLhaus database from memory - completely revised for JSON format
  loadUrlHausDatabase() {
    try {
      if (this.urlHausData) {
        const jsonData = this.urlHausData;

        // Clear the current map
        this.maliciousUrls.clear();

        // Process the JSON data
        // The structure is an object with numbered keys
        let countUrls = 0;

        for (const key in jsonData) {
          if (Object.prototype.hasOwnProperty.call(jsonData, key)) {
            const entry = jsonData[key];
            // Each entry may have one or more URLs
            if (entry && Array.isArray(entry)) {
              for (const item of entry) {
                if (item.url && item.url_status === "online") {
                  // Store the URL with its details
                  const urlDetails = {
                    dateAdded: item.dateadded,
                    threat: item.threat,
                    tags: item.tags,
                    urlhausLink: item.urlhaus_link,
                    reporter: item.reporter
                  };

                  // We'll normalize URLs for better matching
                  const normalizedUrl = this._normalizeUrl(item.url);
                  this.maliciousUrls.set(normalizedUrl, urlDetails);
                  countUrls++;
                }
              }
            }
          }
        }

        console.log(`[Security] Loaded ${countUrls} malicious URLs from URLhaus database`);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Error loading URLhaus database:', error);
      return false;
    }
  }

  // Helper function to normalize URLs for better matching
  _normalizeUrl(url) {
    try {
      const urlObj = new URL(url);
      let hostname = urlObj.hostname.toLowerCase();
      let pathname = urlObj.pathname.replace(/\/+$/, ''); // Remove trailing slashes
      pathname = decodeURIComponent(pathname); // Decode URL-encoded characters
      return hostname + pathname;
    } catch (e) {
      return url.toLowerCase();
    }
  }

  // Check if a URL matches any known malicious URLs
  _checkUrlAgainstDatabase(url) {
    const normalizedUrl = this._normalizeUrl(url);

    // Direct match
    if (this.maliciousUrls.has(normalizedUrl)) {
      return {
        matched: true,
        details: this.maliciousUrls.get(normalizedUrl)
      };
    }

    // Check if the URL is a substring of any malicious URL
    // Or if any malicious URL is a substring of the URL
    for (const [maliciousUrl, details] of this.maliciousUrls.entries()) {
      if (normalizedUrl.includes(maliciousUrl) || maliciousUrl.includes(normalizedUrl)) {
        return {
          matched: true,
          details: details,
          partialMatch: true
        };
      }
    }

    return { matched: false };
  }

  // Check if a download URL is known to be malicious
  async checkDownloadUrl(url) {
    try {
      // Basic URL validation
      const parsedUrl = new URL(url); // Will throw if invalid
      const hostname = parsedUrl.hostname.toLowerCase();

      console.log(`[Security URL Check] Analyzing URL: ${url}`);


      // Check if URL is in cache
      const normalizedUrl = this._normalizeUrl(url);
      if (urlCache.has(normalizedUrl)) {
        const cachedResult = urlCache.get(normalizedUrl);
        if (Date.now() - cachedResult.timestamp < CACHE_DURATION) {
          console.log('[Security URL Check] Using cached result');
          return cachedResult.result;
        }
        // Cache is expired, remove it
        urlCache.delete(normalizedUrl);
      }

      // Check if we need to update the URLhaus database
      console.log(`[Security URL Check] Checking URLhaus database...`);
      // Only try for 3 seconds max to avoid blocking downloads
      const updatePromise = this.updateUrlHausDatabase();
      const timeoutPromise = new Promise(resolve => setTimeout(resolve, 3000));
      await Promise.race([updatePromise, timeoutPromise]);

      // Check if URL is in URLhaus database
      if (this.maliciousUrls.size > 0) {
        console.log(`[Security URL Check] URLhaus database has ${this.maliciousUrls.size} entries`);

        // Check the URL against the URLhaus database
        const urlCheckResult = this._checkUrlAgainstDatabase(url);
        if (urlCheckResult.matched) {
          const details = urlCheckResult.details;
          console.log(`[Security URL Check] 🚨 URL matched in URLhaus malware database!`);
          console.log(`[Security URL Check] Threat type: ${details.threat}`);
          const tags = Array.isArray(details.tags) ? details.tags.join(', ') : (details.tags || 'none');
          console.log(`[Security URL Check] Tags: ${tags}`);
          console.log(`[Security URL Check] URLhaus link: ${details.urlhausLink}`);

          const result = {
            isSafe: false,
            message: `URL matched against known malicious URL in URLhaus database (${details.threat})`,
            details: details
          };

          // Cache the result
          urlCache.set(normalizedUrl, {
            result,
            timestamp: Date.now()
          });

          return result;
        }
      }

      // Cache the safe result
      const result = { isSafe: true, message: 'Download URL appears safe' };
      urlCache.set(normalizedUrl, {
        result,
        timestamp: Date.now()
      });

      console.log('[Security URL Check] All checks passed, URL appears safe');
      return result;

    } catch (error) {
      console.error('[Security URL Check] Error checking download URL:', error);
      return { isSafe: false, message: 'Invalid download URL' };
    }
  }
}

module.exports = DownloadSecurity; 