require('dotenv').config();
const path = require('path');
const fs = require('fs');
const { app } = require('electron');

class Config {
  constructor() {
    // Always try to load API keys from .env file first
    this.apiKeys = {
      googleSafeBrowsingKey: process.env.GOOGLE_SAFE_BROWSING_API_KEY || '',
      virusTotalApiKey: process.env.VIRUS_TOTAL_API_KEY || ''
    };

    // Log environment mode
    const isProduction = process.env.NODE_ENV === 'production';
    console.log(`Running in ${isProduction ? 'production' : 'development'} mode.`);
    
    // This log helps verify if keys are loaded
    console.log(
      'Config Initialized. Google Safe Browsing Key Present:',
      !!this.apiKeys.googleSafeBrowsingKey,
      'VirusTotal Key Present:',
      !!this.apiKeys.virusTotalApiKey
    );
    
    // If keys are missing, try to find the .env file in various locations
    if (!this.apiKeys.googleSafeBrowsingKey || !this.apiKeys.virusTotalApiKey) {
      this.tryLoadEnvFromAlternateLocations();
    }
  }

  // Try to load .env from different locations in case the default location fails
  tryLoadEnvFromAlternateLocations() {
    console.log('Some API keys are missing. Trying alternate .env file locations...');
    
    const possibleLocations = [
      path.join(process.cwd(), '.env'),
      path.join(__dirname, '.env'),
      app ? path.join(app.getPath('userData'), '.env') : null
    ].filter(Boolean);
    
    for (const envPath of possibleLocations) {
      try {
    if (fs.existsSync(envPath)) {
          console.log(`Found .env file at: ${envPath}`);
          
          // Read and parse the .env file manually
          const envContent = fs.readFileSync(envPath, 'utf8');
          const envVars = this.parseEnvFile(envContent);
          
          // Update API keys if found
          if (envVars.GOOGLE_SAFE_BROWSING_API_KEY) {
            this.apiKeys.googleSafeBrowsingKey = envVars.GOOGLE_SAFE_BROWSING_API_KEY;
          }
          
          if (envVars.VIRUS_TOTAL_API_KEY) {
            this.apiKeys.virusTotalApiKey = envVars.VIRUS_TOTAL_API_KEY;
          }
      
          console.log('Updated API keys from alternate .env location:', {
            googleSafeBrowsingKeyFound: !!this.apiKeys.googleSafeBrowsingKey,
            virusTotalApiKeyFound: !!this.apiKeys.virusTotalApiKey
      });
          
          break;
        }
      } catch (err) {
        console.error(`Error checking .env file at ${envPath}:`, err.message);
  }
    }
  }

  // Simple .env file parser
  parseEnvFile(content) {
    const result = {};
    const lines = content.split('\n');
    
    for (const line of lines) {
      const trimmedLine = line.trim();
      if (trimmedLine && !trimmedLine.startsWith('#')) {
        const equalSignIndex = trimmedLine.indexOf('=');
        if (equalSignIndex > 0) {
          const key = trimmedLine.slice(0, equalSignIndex).trim();
          let value = trimmedLine.slice(equalSignIndex + 1).trim();
          
          // Remove quotes if present
          if ((value.startsWith('"') && value.endsWith('"')) || 
              (value.startsWith("'") && value.endsWith("'"))) {
            value = value.slice(1, -1);
          }
          
          result[key] = value;
        }
      }
    }
    
    return result;
  }

  // Getter for other modules to access the API keys
  getApiKeys() {
    return this.apiKeys;
  }
}

module.exports = new Config(); 