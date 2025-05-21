const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { app } = require('electron');

// Store for caching URL checks to avoid repeated lookups
const urlCache = new Map();
const CACHE_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

class DownloadSecurity {
  constructor() {
    this.urlHausDbPath = path.join(app.getPath('userData'), 'urlhaus.json');
    this.urlHausLastUpdate = 0;
    this.maliciousUrls = new Map();
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
      
      // Write the file to disk
      fs.writeFileSync(this.urlHausDbPath, JSON.stringify(response.data));
      
      // Update last update timestamp
      this.urlHausLastUpdate = now;
      
      // Load the database
      this.loadUrlHausDatabase();
      
      return true;
    } catch (error) {
      console.error('Error updating URLhaus database:', error.message || error);
      
      // Check if database already exists, if so, just load it
      if (fs.existsSync(this.urlHausDbPath)) {
        console.log('[Security] Using existing URLhaus database');
        this.loadUrlHausDatabase();
      } else {
        console.log('[Security] No URLhaus database available, security features will be limited');
      }
      
      return false;
    }
  }
  
  // Load the URLhaus database from disk - completely revised for JSON format
  loadUrlHausDatabase() {
    try {
      if (fs.existsSync(this.urlHausDbPath)) {
        const data = fs.readFileSync(this.urlHausDbPath, 'utf8');
        const jsonData = JSON.parse(data);
        
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
      // Basic URL normalization
      const urlObj = new URL(url);
      // Return hostname + pathname without protocol, query params, etc.
      // This helps match URLs regardless of http/https and query parameters
      return urlObj.hostname + urlObj.pathname;
    } catch (e) {
      // If URL parsing fails, return the original URL
      return url;
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
      
      // Quick check for trusted domains to skip further checks
      const trustedDomains = [
        'mozilla.org', 'mozilla.net', 'github.com', 'github.io', 'githubusercontent.com',
        'w3.org', 'google.com', 'gstatic.com', 'googleapis.com', 'microsoft.com', 
        'windows.net', 'wikipedia.org', 'wikimedia.org', 'adobe.com', 'office.com',
        'apple.com', 'icloud.com', 'dropbox.com', 'box.com', 'drive.google.com'
      ];
      
      for (const domain of trustedDomains) {
        if (hostname.endsWith(domain)) {
          console.log(`[Security URL Check] Trusted domain detected: ${domain}`);
          return { isSafe: true, message: 'Download from trusted domain' };
        }
      }
      
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
          console.log(`[Security URL Check] Tags: ${details.tags.join(', ')}`);
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
  
  // Main method to check if a download is safe
  async scanDownload(downloadInfo) {
    const { url } = downloadInfo; // filePath and fileName are no longer used in this method
    
    // First check the URL against URLhaus database
    const urlCheckResult = await this.checkDownloadUrl(url);
    if (!urlCheckResult.isSafe) {
      return urlCheckResult;
    }
    
    // If URL check passes, and no further local file analysis is performed,
    // consider the download safe based on the URL check alone.
    return { isSafe: true, message: 'URL check passed via URLhaus. No further local file analysis performed.' };
  }
}

module.exports = new DownloadSecurity(); 