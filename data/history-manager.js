const fs = require('fs');
const path = require('path');
const { app } = require('electron');

/**
 * History Manager - Simple JSON-based implementation
 * Stores browser history in a JSON file in the user data directory
 */
class HistoryManager {
  constructor() {
    // Use the app's user data directory for storing history
    // This ensures it's writable in both development and production
    const userDataPath = app ? app.getPath('userData') : path.join(__dirname, '..');
    this.historyFile = path.join(userDataPath, 'browser-history.json');
    console.log('History file location:', this.historyFile);
    this.ensureHistoryFile();
  }

  /**
   * Ensure the history file exists
   */
  ensureHistoryFile() {
    try {
      if (!fs.existsSync(this.historyFile)) {
        fs.writeFileSync(this.historyFile, JSON.stringify({ history: [] }), 'utf8');
        console.log('Created new history file at:', this.historyFile);
      }
    } catch (error) {
      console.error('Error creating history file:', error);
    }
  }

  /**
   * Add a page visit to history
   * @param {string} url - The URL of the page
   * @param {string} title - The title of the page
   * @param {string} favicon - The favicon URL (optional)
   * @returns {Promise<boolean>} - Success status
   */
  async addHistoryEntry(url, title, favicon = '') {
    try {
      // Skip adding history for empty or special URLs
      if (!url || url === 'about:blank' || url.startsWith('chrome://') || url.startsWith('file://')) {
        return false;
      }

      // Create history entry
      const entry = {
        id: Date.now().toString(), // Use timestamp as unique ID
        url: url,
        title: title || url,
        favicon: favicon || '',
        visitTime: new Date().toISOString()
      };

      // Read current history
      const historyData = this.readHistory();
      
      // Add new entry at the beginning
      historyData.history.unshift(entry);
      
      // Save history
      fs.writeFileSync(this.historyFile, JSON.stringify(historyData, null, 2), 'utf8');
      console.log('Added to history:', title);
      
      return entry.id;
    } catch (error) {
      console.error('Error adding to history:', error);
      return false;
    }
  }

  /**
   * Legacy method for addHistoryEntry - kept for backward compatibility
   */
  addHistory(url, title, favicon = '') {
    return this.addHistoryEntry(url, title, favicon);
  }

  /**
   * Get all history entries
   * @returns {Array} - Array of history entries
   */
  getHistory() {
    try {
      const historyData = this.readHistory();
      return historyData.history;
    } catch (error) {
      console.error('Error getting history:', error);
      return [];
    }
  }

  /**
   * Search history entries
   * @param {string} query - Search query
   * @returns {Array} - Array of matching history entries
   */
  searchHistory(query) {
    try {
      if (!query) return this.getHistory();
      
      const historyData = this.readHistory();
      const lowerCaseQuery = query.toLowerCase();
      
      return historyData.history.filter(entry => {
        return entry.title.toLowerCase().includes(lowerCaseQuery) || 
               entry.url.toLowerCase().includes(lowerCaseQuery);
      });
    } catch (error) {
      console.error('Error searching history:', error);
      return [];
    }
  }

  /**
   * Delete a specific history entry
   * @param {string} id - ID of the entry to delete
   * @returns {boolean} - Success status
   */
  deleteHistoryEntry(id) {
    try {
      const historyData = this.readHistory();
      const originalLength = historyData.history.length;
      historyData.history = historyData.history.filter(entry => entry.id !== id);
      
      // Only write if something was actually deleted
      if (historyData.history.length !== originalLength) {
      fs.writeFileSync(this.historyFile, JSON.stringify(historyData, null, 2), 'utf8');
        console.log(`Deleted history entry with ID: ${id}`);
      }
      return true;
    } catch (error) {
      console.error('Error deleting history entry:', error);
      return false;
    }
  }

  /**
   * Clear all browsing history
   * @returns {boolean} - Success status
   */
  clearHistory() {
    try {
      fs.writeFileSync(this.historyFile, JSON.stringify({ history: [] }), 'utf8');
      console.log('Cleared all browsing history');
      return true;
    } catch (error) {
      console.error('Error clearing history:', error);
      return false;
    }
  }

  /**
   * Read the history file
   * @returns {Object} - History data
   */
  readHistory() {
    try {
      this.ensureHistoryFile();
      const data = fs.readFileSync(this.historyFile, 'utf8');
      return JSON.parse(data);
    } catch (error) {
      console.error('Error reading history file:', error);
      return { history: [] };
    }
  }
}

// Export a singleton instance
module.exports = new HistoryManager(); 