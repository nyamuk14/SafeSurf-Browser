const { BrowserWindow, app, ipcMain, session, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const downloadSecurity = require('./download-security');
const Store = require('electron-store');
const axios = require('axios');

// Initialize store for saving download preferences
const store = new Store();

class DownloadManager {
  constructor() {
    this.downloads = new Map();
    this.downloadId = 0;
    this.parentWindow = null;
    this.downloadPath = app.getPath('downloads'); // Always use system default download path
    this.isDownloadPanelVisible = false;
    this.securityScanEnabled = true; // Always enable security scanning
    this.activeDownloadUrls = new Set(); // Track active download URLs to prevent duplicates
    this.blockedDownloads = new Set(); // Track blocked downloads by URL+filename
    this.blockedDownloadMap = new Map(); // Map downloadKey to downloadId for blocked entries
  }

  initialize(parentWindow) {
    this.parentWindow = parentWindow;
    
    // Get current settings for download scanning only
    const settings = store.get('settings') || {};
    this.securityScanEnabled = settings.downloadScanning !== false;
    
    // Listen for downloads in the main session
    session.defaultSession.on('will-download', this._handleDownload.bind(this));
    
    // Also listen for downloads in the webview's persistent session
    const webviewSession = session.fromPartition('persist:main');
    if (webviewSession) {
      webviewSession.on('will-download', this._handleDownload.bind(this));
    }
    
    // Monitor ALL webview content creation to capture Right-click > Save Image As events
    app.on('web-contents-created', (event, contents) => {
      if (contents.getType() === 'webview') {
        // Add will-download listener to each webview
        contents.session.on('will-download', this._handleDownload.bind(this));
        
        // Capture context menu clicks for Save Image As
        contents.on('context-menu', (e, params) => {
          // When the user right-clicks on an image
          if (params.mediaType === 'image' && params.srcURL) {
            console.log(`[Security] Detected potential image download: ${params.srcURL}`);
          }
        });
      }
    });
    
    // Create IPC handlers for download interactions
    this._setupIpcHandlers();
    
    console.log('Download manager initialized');
    console.log('Default download path:', this.downloadPath);
    console.log('Security scanning:', this.securityScanEnabled ? 'Enabled' : 'Disabled');
  }
  
  showDownloadManager() {
    console.log('Showing download panel');
    
    // Always show the download panel
    this.isDownloadPanelVisible = true;
    
    // Send downloads to the renderer process
    const downloads = this.getDownloads();
    const payload = {
      isVisible: this.isDownloadPanelVisible,
      downloads: downloads
    };
    console.log('[DM] Sending toggle-download-panel with payload:', payload);
    this.parentWindow.webContents.send('toggle-download-panel', payload);
  }

  hideDownloadManager() {
    console.log('Hiding download panel');
    this.isDownloadPanelVisible = false;
    
    // Notify renderer to hide the panel
    this.parentWindow.webContents.send('toggle-download-panel', {
      isVisible: false,
      downloads: []
    });
  }

  _setupIpcHandlers() {
    // Handle showing downloads panel
    ipcMain.on('show-downloads', () => {
      console.log('Received show-downloads event');
      this.showDownloadManager();
    });

    // Handle getting all downloads
    ipcMain.handle('get-downloads', () => {
      return this.getDownloads();
    });

    // Handle clearing all downloads
    ipcMain.on('clear-downloads', () => {
      console.log('Clearing all downloads');
      this.downloads.clear();
      
      // Send event to main window
      this.parentWindow.webContents.send('downloads-cleared');
    });
    
    // Handle download operations
    ipcMain.on('cancel-download', (event, id) => {
      console.log('Cancelling download:', id);
      const download = this.downloads.get(id);
      if (download && download.item && !download.item.isDestroyed()) {
        download.item.cancel();
        download.state = 'cancelled';
        
        // Send update to main window
        const downloadToSend = {...download};
        delete downloadToSend.item;
        this.parentWindow.webContents.send('download-updated', downloadToSend);
      }
    });

    ipcMain.on('clear-download', (event, id) => {
      console.log('Clearing download from list:', id);
      this.downloads.delete(id);
      
      // Send event to main window
      this.parentWindow.webContents.send('download-removed', id);
    });

    ipcMain.on('retry-download', (event, id) => {
      console.log('Retrying download:', id);
      const download = this.downloads.get(id);
      
      if (download && download.url) {
        // Set up a new download item
        this.parentWindow.webContents.downloadURL(download.url);
        
        // Remove the old download
        this.downloads.delete(id);
        this.parentWindow.webContents.send('download-removed', id);
      }
    });

    // Handle download panel close
    ipcMain.on('close-download-panel', () => {
      this.hideDownloadManager();
    });
  }

  async _performPreDownloadScan(url, fileName) {
    // Skip scanning if security is disabled
    if (!this.securityScanEnabled) {
      return { isSafe: true, message: 'Security scanning is disabled' };
    }
    
    try {
      console.log(`-------------------------------------------------------------`);
      console.log(`[Security] SCANNING: ${fileName} from ${url}`);
      console.log(`-------------------------------------------------------------`);
      
      // Show scanning alert to user
      this.parentWindow.webContents.send('security-alert', {
        message: `Scanning download: ${fileName}...`,
        type: 'warning'
      });
      
      // Create a progress tracker for UI
      const scanProgress = {
        fileName,
        url,
        state: 'scanning',
        progress: 0
      };
      
      // Check the URL against threat databases (use backend)
      console.log(`[Security] Checking URL against threat databases (backend): ${url}`);
      let urlCheckResult;
      try {
        const response = await axios.post('https://safesurf-browser-production.up.railway.app/check-urlhaus', { url });
        urlCheckResult = response.data;
      } catch (err) {
        urlCheckResult = { isSafe: false, message: 'Backend error: ' + err.message };
      }
      scanProgress.progress = 75;
      
      if (!urlCheckResult.isSafe) {
        console.warn(`[Security] ⚠️ URL MALICIOUS: ${url}`);
        console.warn(`[Security] Reason: ${urlCheckResult.message}`);
        console.log(`-------------------------------------------------------------`);
        
        // Show detailed information about the URL scan in the console
        if (urlCheckResult.detections) {
          console.log(`[Security] Detections by vendor:`);
          Object.entries(urlCheckResult.detections).forEach(([vendor, result]) => {
            console.log(`- ${vendor}: ${result}`);
          });
        }
        
        return urlCheckResult;
      }
      
      // If URL check passes
      console.log(`[Security] URL check passed: ${urlCheckResult.message}`);
      
      // If both checks pass
      console.log(`[Security] Pre-download scan complete: File appears safe`);
      console.log(`-------------------------------------------------------------`);
      return { isSafe: true, message: 'Pre-download scan passed' };
    } catch (error) {
      console.error('[Security] Error during pre-download scan:', error);
      console.log(`-------------------------------------------------------------`);
      // In case of error, still allow the download but log the issue
      return { 
        isSafe: true, 
        warning: true,
        message: 'Error during security scan. Use caution with this file.' 
      };
    }
  }

  _handleDownload(event, item, webContents) {
    const id = this.downloadId++;
    // Get and sanitize the filename
    const originalFilename = item.getFilename();
    const fileName = this._sanitizeFilename(originalFilename);
    const url = item.getURL();
    
    // Unique key for this download
    const downloadKey = `${url}_${fileName}`;
    
    // If this download was previously blocked, block it instantly
    if (this.blockedDownloads.has(downloadKey)) {
      // If already in downloads list, do not add again
      if (this.blockedDownloadMap.has(downloadKey)) {
        this.parentWindow.webContents.send('security-alert', {
          message: `Download Blocked: This file was previously blocked as malicious.`,
          type: 'error'
        });
        item.cancel();
        return;
      }
      // Otherwise, add to downloads and map as before
      console.warn(`[Security] Instantly blocking previously blocked malicious download: ${fileName} from ${url}`);
      const blockedDownload = {
        id,
        fileName,
        url,
        state: 'blocked',
        receivedBytes: 0,
        totalBytes: 0,
        startTime: Date.now(),
        endTime: Date.now(),
        securityInfo: 'This file was previously blocked as malicious.'
      };
      this.downloads.set(id, blockedDownload);
      this.blockedDownloadMap.set(downloadKey, id);
      this.parentWindow.webContents.send('download-started', blockedDownload);
      if (!this.isDownloadPanelVisible) {
        this.isDownloadPanelVisible = true;
        this.parentWindow.webContents.send('toggle-download-panel', {
          isVisible: true,
          downloads: this.getDownloads()
        });
      }
      this.parentWindow.webContents.send('security-alert', {
        message: `Download Blocked: This file was previously blocked as malicious.`,
        type: 'error'
      });
      item.cancel();
      return;
    }
    // Only skip if the download is currently in progress
    if (this.activeDownloadUrls.has(downloadKey)) {
      console.log(`[Download] Skipping duplicate download in progress: ${fileName} from ${url}`);
      return;
    }
    // Add to active downloads set to prevent duplicates in progress
    this.activeDownloadUrls.add(downloadKey);
    
    // If download scanning is disabled, proceed directly without security checks
    if (!this.securityScanEnabled) {
      console.log(`[Download] Security scanning disabled. Proceeding with download: ${fileName} from ${url}`);
      
      // No pause/security check needed, proceed immediately
      const savePath = path.join(this.downloadPath, fileName);
      item.setSavePath(savePath);
      
      const download = {
        id,
        fileName,
        path: savePath,
        url,
        state: 'downloading',
        receivedBytes: 0,
        totalBytes: item.getTotalBytes(),
        startTime: Date.now(),
        item: item
      };

      this.downloads.set(id, download);

      // Notify about new download
      const downloadToSend = {...download};
      delete downloadToSend.item;
      this.parentWindow.webContents.send('download-started', downloadToSend);

      // Automatically show the download panel when a download starts
      if (!this.isDownloadPanelVisible) {
        this.isDownloadPanelVisible = true;
        this.parentWindow.webContents.send('toggle-download-panel', {
          isVisible: true,
          downloads: this.getDownloads()
        });
      }

      // Set up progress updates
      item.on('updated', (event, state) => {
        download.state = state;
        download.receivedBytes = item.getReceivedBytes();
        
        // Calculate remaining time and speed
        const elapsed = (Date.now() - download.startTime) / 1000;
        const bytesPerSecond = elapsed > 0 ? download.receivedBytes / elapsed : 0;
        download.speed = bytesPerSecond;
        
        if (download.totalBytes > 0 && bytesPerSecond > 0) {
          const remaining = (download.totalBytes - download.receivedBytes) / bytesPerSecond;
          download.remainingTime = remaining;
        }
        
        // Send update to main window
        const downloadToSend = {...download};
        delete downloadToSend.item;
        this.parentWindow.webContents.send('download-updated', downloadToSend);
      });

      // Handle download completion without security scanning
      item.once('done', (event, state) => {
        download.state = state;
        download.receivedBytes = state === 'completed' ? item.getTotalBytes() : download.receivedBytes;
        download.endTime = Date.now();
        
        // Remove the item reference as it's no longer needed
        delete download.item;
        
        // Remove from active downloads tracking
        this.activeDownloadUrls.delete(downloadKey);
        
        console.log(`[Download] Download ${fileName} ${state}`);
        
        // Send update to main window
        this.parentWindow.webContents.send('download-updated', download);
      });
      
      return;
    }
    
    // If scanning is enabled, pause the download until we complete security scan
    item.pause();
    
    console.log(`[Download] New download requested: ${fileName} from ${url}`);
    
    // Perform pre-download security scan
    this._performPreDownloadScan(url, fileName).then(scanResult => {
      if (!scanResult.isSafe) {
        // Block the download if it's not safe
        console.warn(`[Security] 🛑 BLOCKING MALICIOUS DOWNLOAD: ${fileName} from ${url}`);
        console.warn(`[Security] Reason: ${scanResult.message}`);
        // Add to blockedDownloads set
        this.blockedDownloads.add(downloadKey);
        // Add to blockedDownloadMap if not already present
        if (!this.blockedDownloadMap.has(downloadKey)) {
          this.blockedDownloadMap.set(downloadKey, id);
          // Create a blocked download entry
          const blockedDownload = {
            id,
            fileName,
            url,
            state: 'blocked',
            receivedBytes: 0,
            totalBytes: 0,
            startTime: Date.now(),
            endTime: Date.now(),
            securityInfo: scanResult.message
          };
          // Add to downloads map
          this.downloads.set(id, blockedDownload);
          // Send to renderer
          this.parentWindow.webContents.send('download-started', blockedDownload);
          // Show download panel with warning
          if (!this.isDownloadPanelVisible) {
            this.isDownloadPanelVisible = true;
            this.parentWindow.webContents.send('toggle-download-panel', {
              isVisible: true,
              downloads: this.getDownloads()
            });
          }
        }
        // Show security alert
        this.parentWindow.webContents.send('security-alert', {
          message: `Download Blocked: ${scanResult.message}`,
          type: 'error'
        });
        // Cancel the download
        item.cancel();
        return;
      }
      
      // If there's a warning but file is still considered safe, show it
      if (scanResult.warning) {
        this.parentWindow.webContents.send('security-alert', {
          message: scanResult.message,
          type: 'warning'
        });
      } else {
        // Show success message for clean files
        this.parentWindow.webContents.send('security-alert', {
          message: `Download verified safe: ${fileName}`,
          type: 'success'
        });
      }
      
      // Resume the download since it passed security checks
      item.resume();
      
      // Set the save path to the download directory
      const savePath = path.join(this.downloadPath, fileName);
      item.setSavePath(savePath);
      
      const download = {
        id,
        fileName,
        path: savePath,
        url,
        state: 'downloading',
        receivedBytes: 0,
        totalBytes: item.getTotalBytes(),
        startTime: Date.now(),
        item: item
      };

      this.downloads.set(id, download);

      // Notify about new download
      // Remove the item property before sending to renderer
      const downloadToSend = {...download};
      delete downloadToSend.item;
      this.parentWindow.webContents.send('download-started', downloadToSend);

      // Automatically show the download panel when a download starts
      if (!this.isDownloadPanelVisible) {
        this.isDownloadPanelVisible = true;
        this.parentWindow.webContents.send('toggle-download-panel', {
          isVisible: true,
          downloads: this.getDownloads()
        });
      }

      item.on('updated', (event, state) => {
        download.state = state;
        download.receivedBytes = item.getReceivedBytes();
        
        // Calculate remaining time and speed
        const elapsed = (Date.now() - download.startTime) / 1000; // seconds
        const bytesPerSecond = elapsed > 0 ? download.receivedBytes / elapsed : 0;
        download.speed = bytesPerSecond;
        
        if (download.totalBytes > 0 && bytesPerSecond > 0) {
          const remaining = (download.totalBytes - download.receivedBytes) / bytesPerSecond;
          download.remainingTime = remaining;
        }
        
        // Send update to main window
        const downloadToSend = {...download};
        delete downloadToSend.item;
        this.parentWindow.webContents.send('download-updated', downloadToSend);
      });

      item.once('done', async (event, state) => {
        download.state = state;
        download.receivedBytes = state === 'completed' ? item.getTotalBytes() : download.receivedBytes;
        download.endTime = Date.now();
        
        // Remove the item reference as it's no longer needed
        delete download.item;
        
        // Remove from active downloads tracking
        this.activeDownloadUrls.delete(downloadKey);
        
        console.log(`[Download] Download ${fileName} ${state}`);
        
        if (state === 'completed') {
          // Perform post-download security scan
          try {
            console.log(`-------------------------------------------------------------`);
            console.log(`[Security] POST-DOWNLOAD SCAN: ${fileName}`);
            console.log(`-------------------------------------------------------------`);
            
            // Show scanning alert to user
            this.parentWindow.webContents.send('security-alert', {
              message: `Scanning downloaded file: ${fileName}...`,
              type: 'warning'
            });
            
            const scanResult = await downloadSecurity.scanDownload({
              url: download.url,
              filePath: download.path,
              fileName: download.fileName
            });
            
            download.securityScanResult = scanResult;
            
            if (!scanResult.isSafe) {
              // Mark the download as malicious but don't delete it
              download.state = 'malicious';
              console.warn(`[Security] ⚠️ MALICIOUS FILE DETECTED: ${download.fileName}`);
              console.warn(`[Security] Reason: ${scanResult.message}`);
              
              // Show detailed information about the scan in the console
              if (scanResult.detections) {
                console.log(`[Security] Detections by vendor:`);
                Object.entries(scanResult.detections).forEach(([vendor, result]) => {
                  console.log(`- ${vendor}: ${result}`);
                });
              }
              
              // Show security alert
              this.parentWindow.webContents.send('security-alert', {
                message: `Security Warning: ${scanResult.message}`,
                type: 'error'
              });
            } else {
              console.log(`[Security] Post-download scan complete: File is safe`);
              console.log(`-------------------------------------------------------------`);
              
              // Show success message for clean files
              this.parentWindow.webContents.send('security-alert', {
                message: `Download verified safe: ${fileName}`,
                type: 'success'
              });
            }
          } catch (error) {
            console.error('[Security] Error scanning downloaded file:', error);
          }
        }
        
        // Send update to main window
        this.parentWindow.webContents.send('download-updated', download);
      });
    }).catch(error => {
      console.error('[Security] Error in pre-download scan:', error);
      // Remove from active downloads tracking in case of error
      this.activeDownloadUrls.delete(downloadKey);
      // Allow the download to proceed in case of error
      const savePath = path.join(this.downloadPath, fileName);
      item.setSavePath(savePath);
      item.resume();
    });
  }
  
  /**
   * Get all downloads
   * @returns {Array} - Array of download objects
   */
  getDownloads() {
    return Array.from(this.downloads.values()).map(download => {
      // Create a copy without the item property
      const downloadCopy = {...download};
      delete downloadCopy.item;
      return downloadCopy;
    });
  }
  
  /**
   * Clear all downloads from the list
   */
  clearDownloads() {
    console.log('Clearing all downloads from list');
    
    // Cancel any active downloads
    this.downloads.forEach(download => {
      if (download.state === 'progressing' && download.item && !download.item.isDestroyed()) {
        download.item.cancel();
      }
    });
    
    // Clear the downloads map
    this.downloads.clear();
    
    // Clear the blockedDownloadMap
    this.blockedDownloadMap.clear();
    
    // Notify the main window
    this.parentWindow.webContents.send('downloads-cleared');
  }
  
  /**
   * Update the download security scanning setting
   * @param {boolean} enabled - Whether scanning is enabled or not
   */
  updateSecurityScanning(enabled) {
    console.log(`Updating download security scanning to: ${enabled ? 'Enabled' : 'Disabled'}`);
    this.securityScanEnabled = enabled;
  }

  // Helper function to minimally sanitize filenames for Windows
  // Only replaces illegal characters that would cause errors
  _sanitizeFilename(filename) {
    if (!filename) return 'download';
    
    // Only replace characters that are actually illegal in Windows
    // < > : " / \ | ? *
    return filename.replace(/[<>:"\/\\|?*]/g, '_');
  }
}

module.exports = new DownloadManager(); 