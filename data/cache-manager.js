const path = require('path');
const fs = require('fs').promises;
const { app } = require('electron');
const historyManager = require('./history-manager');

// Use the app's user data directory for cache storage
const getUserDataPath = () => {
  if (app) {
    return app.getPath('userData');
  }
  // Fallback to project directory if app is not available
  return process.cwd();
};

class CacheManager {
  constructor() {
    const userDataPath = getUserDataPath();
    this.cachePath = path.join(userDataPath, 'Cache');
    console.log('Using cache path:', this.cachePath);
    this.initCache();
    this.cacheEntries = new Map(); // In-memory cache tracking
  }

  async initCache() {
    try {
      await fs.mkdir(this.cachePath, { recursive: true });
    } catch (error) {
      console.error('Error creating cache directory:', error);
    }
  }

  // Generate a cache file path for a URL
  generateCachePath(url) {
    const urlHash = Buffer.from(url).toString('base64').replace(/[/+=]/g, '_');
    return path.join(this.cachePath, `${urlHash}.cache`);
  }

  // Cache a page or resource
  async cacheResource(url, data, historyId) {
    try {
      const cachePath = this.generateCachePath(url);
      await fs.writeFile(cachePath, data);
      
      // Track cache entry in memory
      this.cacheEntries.set(url, {
        url: url,
        cachePath: cachePath,
        historyId: historyId,
        timestamp: Date.now()
      });
      
      return cachePath;
    } catch (error) {
      console.error('Error caching resource:', error);
      throw error;
    }
  }

  // Get cached resource
  async getCachedResource(url) {
    try {
      const cachePath = this.generateCachePath(url);
      const data = await fs.readFile(cachePath);
      return data;
    } catch (error) {
      // Cache miss or error
      return null;
    }
  }

  // Clean up cache files older than a specific timeframe
  async cleanupCache(maxAgeMs = 7 * 24 * 60 * 60 * 1000) { // Default: 1 week
    try {
      const now = Date.now();
      const files = await fs.readdir(this.cachePath);
      
      for (const file of files) {
        try {
          const filePath = path.join(this.cachePath, file);
          const stats = await fs.stat(filePath);
          
          // If file is older than max age, delete it
          if (now - stats.mtime.getTime() > maxAgeMs) {
            await fs.unlink(filePath);
            console.log('Removed old cache file:', file);
          }
        } catch (error) {
          console.error('Error checking/removing cache file:', error);
        }
      }
      
      // Clean up in-memory cache tracking
      for (const [url, entry] of this.cacheEntries.entries()) {
        if (now - entry.timestamp > maxAgeMs) {
          this.cacheEntries.delete(url);
        }
      }
    } catch (error) {
      console.error('Error during cache cleanup:', error);
    }
  }

  // Get total cache size
  async getCacheSize() {
    try {
      const files = await fs.readdir(this.cachePath);
      let totalSize = 0;
      
      for (const file of files) {
        try {
          const filePath = path.join(this.cachePath, file);
          const stats = await fs.stat(filePath);
          totalSize += stats.size;
        } catch (error) {
          console.error('Error getting file stats:', error);
        }
      }
      
      return totalSize;
    } catch (error) {
      console.error('Error calculating cache size:', error);
      return 0;
    }
  }

  // Clear all cache files
  async clearCache() {
    try {
      const files = await fs.readdir(this.cachePath);
      
      for (const file of files) {
        try {
          await fs.unlink(path.join(this.cachePath, file));
        } catch (error) {
          console.error('Error removing cache file:', error);
        }
      }
      
      // Reset in-memory cache tracking
      this.cacheEntries.clear();
      
      console.log('Cache cleared successfully');
      return true;
    } catch (error) {
      console.error('Error clearing cache:', error);
      return false;
    }
  }
}

module.exports = new CacheManager(); 