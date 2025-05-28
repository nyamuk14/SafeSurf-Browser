const { contextBridge, ipcRenderer } = require('electron');

// Safely expose specific APIs to the renderer process
contextBridge.exposeInMainWorld('electronAPI', {
  // Browser navigation
  navigateTo: (url) => ipcRenderer.send('navigate-to', url),
  
  // Security-related functions
  checkPhishing: (url) => ipcRenderer.invoke('check-phishing', url),
  scanDownload: (fileInfo) => ipcRenderer.invoke('scan-download', fileInfo),
  
  // Cache management
  clearCache: () => ipcRenderer.invoke('clear-cache'),
  getCacheSize: () => ipcRenderer.invoke('getCacheSize'),
  
  // Download manager
  showDownloads: () => {
    console.log('Sending show-downloads event');
    ipcRenderer.send('show-downloads');
  },
  downloadURL: (url) => ipcRenderer.send('download-url', url),
  testDownload: () => ipcRenderer.send('test-download'),
  
  // Browser settings
  getSettings: () => ipcRenderer.invoke('get-settings'),
  updateSettings: (settings) => ipcRenderer.invoke('update-settings', settings),
  
  // API key management
  importApiKeys: () => ipcRenderer.invoke('import-api-keys'),
  exportApiKeys: () => ipcRenderer.invoke('export-api-keys'),
  
  // History functions
  addHistoryEntry: (entry) => ipcRenderer.invoke('add-history-entry', entry),
  getHistory: () => ipcRenderer.invoke('get-history'),
  searchHistory: (query) => ipcRenderer.invoke('search-history', query),
  clearHistory: () => ipcRenderer.invoke('clear-history'),
  deleteHistoryEntry: (id) => ipcRenderer.invoke('delete-history-entry', id),
  
  // Event listeners
  onURLUpdate: (callback) => {
    ipcRenderer.on('url-update', (event, url) => callback(url));
  },
  onSecurityAlert: (callback) => {
    ipcRenderer.on('security-alert', (event, message) => callback(message));
  },
  onSettingsUpdated: (callback) => ipcRenderer.on('settings-updated', callback),
  onHttpBlocked: (callback) => {
    ipcRenderer.on('http-blocked', (event, data) => callback(data));
  },
  allowHttpUrl: (url) => ipcRenderer.send('allow-http-url', url)
});

// Expose download manager APIs
contextBridge.exposeInMainWorld('downloadAPI', {
  getDownloads: () => ipcRenderer.invoke('get-downloads'),
  clearDownloads: () => ipcRenderer.send('clear-downloads'),
  retryDownload: (id) => ipcRenderer.send('retry-download', id),
  cancelDownload: (id) => ipcRenderer.send('cancel-download', id),
  clearDownload: (id) => ipcRenderer.send('clear-download', id),
  closeDownloadPanel: () => ipcRenderer.send('close-download-panel'),
  
  // Events
  onDownloadStarted: (callback) => {
    ipcRenderer.on('download-started', (event, download) => callback(download));
    return () => ipcRenderer.removeListener('download-started', callback);
  },
  
  onDownloadUpdated: (callback) => {
    ipcRenderer.on('download-updated', (event, download) => callback(download));
    return () => ipcRenderer.removeListener('download-updated', callback);
  },
  
  onDownloadRemoved: (callback) => {
    ipcRenderer.on('download-removed', (event, id) => callback(id));
    return () => ipcRenderer.removeListener('download-removed', callback);
  },

  onToggleDownloadPanel: (callback) => {
    console.log('[Preload] Setting up listener for toggle-download-panel');
    ipcRenderer.on('toggle-download-panel', (event, data) => callback(data));
    return () => ipcRenderer.removeListener('toggle-download-panel', callback);
  },
  
  onDownloadsCleared: (callback) => {
    ipcRenderer.on('downloads-cleared', () => callback());
    return () => ipcRenderer.removeListener('downloads-cleared', callback);
  }
});

// Export default settings
const defaultSettings = {
  phishingProtection: true,
  downloadScanning: true
}; 