// Import Node.js core modules
const { app, BrowserWindow, session, protocol, ipcMain, dialog, clipboard } = require('electron');
const path = require('path');
const url = require('url');
const fs = require('fs');
const Store = require('electron-store');
require('dotenv').config();

// In production mode, we'll log to a file instead of disabling logs completely
if (process.env.NODE_ENV === 'production') {
  // Create a simple logging function that writes to a file
  const logFile = path.join(app.getPath('userData'), 'logs.txt');
  
  // Create a simple timestamp function
  const getTimestamp = () => {
    const now = new Date();
    return `${now.toISOString()}`;
  };
  
  // Log file header
  try {
    fs.writeFileSync(logFile, `\n---- APPLICATION STARTED ${getTimestamp()} ----\n`, { flag: 'a' });
  } catch (err) {
    // If we can't write to the log file, fall back to original console methods
    console.error('Could not write to log file:', err);
  }
  
  // Override console methods to write to file
  const originalLog = console.log;
  const originalWarn = console.warn;
  const originalError = console.error;
  
  console.log = function() {
    try {
      const args = Array.from(arguments).join(' ');
      fs.appendFileSync(logFile, `[LOG] ${getTimestamp()}: ${args}\n`);
    } catch (e) {
      // Fall back to original console if file write fails
      originalLog.apply(console, arguments);
    }
  };
  
  console.warn = function() {
    try {
      const args = Array.from(arguments).join(' ');
      fs.appendFileSync(logFile, `[WARN] ${getTimestamp()}: ${args}\n`);
    } catch (e) {
      originalWarn.apply(console, arguments);
    }
  };
  
  console.error = function() {
    try {
      const args = Array.from(arguments).join(' ');
      fs.appendFileSync(logFile, `[ERROR] ${getTimestamp()}: ${args}\n`);
    } catch (e) {
      originalError.apply(console, arguments);
    }
  };
  
  // Let's log where our log file is located
  console.log(`Logging to file: ${logFile}`);
}

// Import config module for API keys
const config = require('./config');

// Import security modules
const phishingDetection = require('./security/phishing-detection');
let downloadSecurity;
try {
  downloadSecurity = require('./security/download-security');
  console.log('Download security module loaded successfully');
} catch (error) {
  console.error('Error loading download security module:', error.message);
  // Provide a fallback implementation with basic functions
  downloadSecurity = {
    scanDownload: () => ({ isSafe: true, message: 'Security scanning unavailable' }),
    checkDownloadUrl: () => ({ isSafe: true, message: 'URL checking unavailable' }),
    updateUrlHausDatabase: () => Promise.resolve(false)
  };
}
const downloadManager = require('./security/download-manager');

// Import data management modules
const historyManager = require('./data/history-manager'); // Use the new simple manager
const cacheManager = require('./data/cache-manager');

// Initialize store for saving user preferences and security settings
const store = new Store();

// Global variables
let mainWindow; // Keep a global reference of the window object to prevent garbage collection

// Default settings
const defaultSettings = {
  phishingProtection: true,
  downloadScanning: true
};

// Load settings from store
let settings = store.get('settings') || defaultSettings;

// Clean up any existing downloadPath from settings
if (settings.downloadPath) {
  console.log('Removing downloadPath from settings');
  delete settings.downloadPath;
  store.set('settings', settings);
}

// Create the browser window
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    title: 'SafeSurf Browser',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js'),
      webviewTag: true,
      webSecurity: true,
      sandbox: true,
      plugins: true // Enable plugins
    }
  });

  // Set a standard user agent to avoid detection issues with Google and other sites
  session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
    details.requestHeaders['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';
    callback({ requestHeaders: details.requestHeaders });
  });

  // Enable PDF viewer and plugins before creating window
  app.commandLine.appendSwitch('enable-plugins');
  app.commandLine.appendSwitch('enable-pdf-viewer');
  app.commandLine.appendSwitch('enable-javascript-harmony');
  app.commandLine.appendSwitch('enable-features', 'PdfViewerUpdate');
  app.commandLine.appendSwitch('disable-site-isolation-trials');

  // Set CSP for the main window
  if (mainWindow && mainWindow.webContents && mainWindow.webContents.session) {
    mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
      if (details.url.startsWith('file://')) {
        callback({
          responseHeaders: {
            ...details.responseHeaders,
            'Content-Security-Policy': [
              "default-src 'self';" +
              "script-src 'self' 'unsafe-inline';" +
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;" +
              "font-src 'self' https://fonts.gstatic.com;" +
              "img-src 'self' data: https:;" +
              "connect-src 'self' https:;" +
              "media-src 'self' blob:;" +
              "object-src 'none'"
            ]
          }
        });
      } else {
        callback({ responseHeaders: details.responseHeaders });
      }
    });
  }

  // Set CSP for webviews
  app.on('web-contents-created', (event, contents) => {
    if (contents.getType() === 'webview') {
      // Set webview-specific preferences
      contents.setWindowOpenHandler(({ url }) => {
        if (url.startsWith('https://')) {
          return { action: 'allow' };
        }
        return { action: 'deny' };
      });

      // Set security headers for webview content
      contents.session.webRequest.onHeadersReceived((details, callback) => {
        callback({
          responseHeaders: {
            ...details.responseHeaders,
            'Content-Security-Policy': [
              "default-src 'self' https:;" +
              "script-src 'self' https: 'unsafe-inline';" +
              "style-src 'self' https: 'unsafe-inline';" +
              "img-src 'self' https: data: blob:;" +
              "font-src 'self' https: data:;" +
              "connect-src 'self' https:;" +
              "media-src 'self' https: data: blob:;" +
              "object-src 'none';" +
              "frame-src 'self' https:;"
            ]
          }
        });
      });

      // Add context menu for right clicks
      contents.on('context-menu', (event, params) => {
        const { x, y, linkURL, srcURL, mediaType, selectionText, isEditable } = params;
        
        const menuTemplate = [];
        
        // Handle text selection
        if (selectionText) {
          menuTemplate.push(
            { label: 'Copy', role: 'copy' },
            { type: 'separator' }
          );
        }
        
        // Handle links
        if (linkURL) {
          menuTemplate.push(
            { label: 'Open Link in New Tab', click: () => contents.loadURL(linkURL) },
            { label: 'Copy Link Address', click: () => clipboard.writeText(linkURL) },
            { label: 'Download Link', click: () => contents.downloadURL(linkURL) },
            { type: 'separator' }
          );
        }
        
        // Handle images
        if (mediaType === 'image') {
          menuTemplate.push(
            { label: 'Save Image As...', click: () => contents.downloadURL(srcURL) },
            { label: 'Copy Image', role: 'copyImage' },
            { type: 'separator' }
          );
        }
        
        // Add Save Page As option for all contexts
        menuTemplate.push(
          { 
            label: 'Save Page As...', 
            click: async () => {
              try {
                const { canceled, filePath } = await dialog.showSaveDialog({
                  title: 'Save Page',
                  defaultPath: path.join(app.getPath('downloads'), 
                    path.basename(contents.getURL()) || 'webpage.html'),
                  filters: [
                    { name: 'Web Page', extensions: ['html'] },
                    { name: 'All Files', extensions: ['*'] }
                  ]
                });
                
                if (!canceled && filePath) {
                  await contents.savePage(filePath, 'HTMLComplete');
                  console.log(`Page saved to: ${filePath}`);
                }
              } catch (error) {
                console.error('Error saving page:', error);
              }
            } 
          },
          { type: 'separator' }
        );
        
        // Add special handling for downloading text content pages
        menuTemplate.push(
          { 
            label: 'Download Page Content', 
            click: () => {
              // Create a temporary URL to download the current page content
              contents.executeJavaScript(`
                (function() {
                  const pageContent = document.body.innerText;
                  const url = window.location.href;
                  const fileName = url.split('/').pop() || 'content.txt';
                  
                  // For EICAR test file, ensure correct filename
                  if (url.includes('eicar.com') || pageContent.includes('EICAR-STANDARD-ANTIVIRUS-TEST-FILE')) {
                    return {
                      url: URL.createObjectURL(new Blob([pageContent], {type: 'text/plain'})),
                      fileName: 'eicar.com.txt' 
                    };
                  }
                  
                  return {
                    url: URL.createObjectURL(new Blob([pageContent], {type: 'text/plain'})),
                    fileName: fileName
                  };
                })()
              `).then(result => {
                if (result && result.url) {
                  // Use Electron's download API
                  contents.downloadURL(result.url);
                  console.log(`Downloading content as: ${result.fileName}`);
                }
              }).catch(err => console.error('Error downloading content:', err));
            }
          },
          { type: 'separator' }
        );
        
        // Always add back/forward
        menuTemplate.push(
          { label: 'Back', click: () => contents.goBack(), enabled: contents.canGoBack() },
          { label: 'Forward', click: () => contents.goForward(), enabled: contents.canGoForward() },
          { label: 'Reload', click: () => contents.reload() }
        );
        
        // Create and show the menu if we have items
        if (menuTemplate.length > 0) {
          const { Menu } = require('electron');
          const menu = Menu.buildFromTemplate(menuTemplate);
          menu.popup({ window: mainWindow, x, y });
        }
      });
    }
  });

  // Load the index.html file
  mainWindow.loadFile('index.html');

  // Setup webview security after window creation
  setupWebviewSecurity();

  // Initialize the download manager
  downloadManager.initialize(mainWindow);

  // Add page to history when loaded
  if (mainWindow && mainWindow.webContents) {
    mainWindow.webContents.on('page-title-updated', (event, title) => {
      let url;
      if (mainWindow && mainWindow.webContents) {
        url = mainWindow.webContents.getURL();
      }
      const favicon = `${url}/favicon.ico`; // Basic favicon URL (you might want to improve this)
      addPageToHistory(url, title, favicon);
    });
  }

  // Handle window close
  mainWindow.on('closed', function () {
    mainWindow = null;
  });
}

// HTTPS Enforcement (Simplified)
function setupHttpsEnforcement() {
  const allowedHttpUrls = new Set(); // Track user-allowed HTTP URLs for this session
  session.defaultSession.webRequest.onBeforeRequest({ urls: ["http://*/*"] }, (details, callback) => {
    try {
      const url = details.url;
      const domain = new URL(url).hostname;
      // Skip local resources and special protocols
      if (
        domain === 'localhost' ||
        domain === '127.0.0.1' ||
        url.startsWith('file://') ||
        url.startsWith('safe://') ||
        url.startsWith('devtools://')
      ) {
        callback({});
        return;
      }
      // If user has allowed this URL, let it through
      if (allowedHttpUrls.has(url)) {
        callback({});
        return;
      }
      // Otherwise, block and show warning with option to continue
      if (mainWindow && mainWindow.webContents) {
        mainWindow.webContents.send('http-blocked', { url });
      }
      callback({ cancel: true });
    } catch (error) {
      console.error('Error in HTTP enforcement:', error);
      callback({});
    }
  });

  // Block mixed content (HTTP content in HTTPS pages) - This part remains useful
  session.defaultSession.webRequest.onBeforeRequest({ urls: ["http://*/*"] }, (details, callback) => {
    // Only apply to resources loaded within HTTPS pages
    if (details.initiator && details.initiator.startsWith('https://')) {
      try {
        const url = new URL(details.url);
        mainWindow?.webContents.send('security-alert', {
          message: `Blocked insecure content from ${url.hostname}`,
          type: 'warning'
        });
        callback({ cancel: true });
      } catch (error) {
        console.error('Error blocking mixed content:', error);
        callback({ cancel: true }); // Block on error to be safe
      }
    } else {
      callback({});
    }
  });
}

// Handle page loads for caching
function setupCaching() {
  session.defaultSession.webRequest.onCompleted(async (details) => {
    if (details.resourceType === 'mainFrame' && details.method === 'GET') {
      try {
        // Skip about:blank, chrome, devtools, and file URLs
        if (details.url.startsWith('about:') || 
            details.url.startsWith('chrome:') || 
            details.url.startsWith('devtools://') || 
            details.url.startsWith('file://')) {
          return;
        }
        
        console.log('[Cache] onCompleted triggered for mainFrame:', details.url);
        
        // Wait a moment for the page to fully render
        setTimeout(async () => {
          console.log('[Cache] setTimeout executing for:', details.url);
          try {
            // Get the title from the webview
            let title;
            if (mainWindow && mainWindow.webContents) {
              title = mainWindow.webContents.getTitle();
            }
            console.log('[Cache] Got title:', title);
            
            // Try to get favicon 
            let favicon = '';
            if (mainWindow && mainWindow.webContents) {
              favicon = await mainWindow.webContents.executeJavaScript(`
                document.querySelector('link[rel="icon"]')?.href || 
                document.querySelector('link[rel="shortcut icon"]')?.href ||
                (window.location.origin + '/favicon.ico')
              `);
            }
            
            // Add to history and get the history ID
            const historyId = await historyManager.addHistoryEntry(
              details.url,
              title,
              favicon
            );
            
            console.log('[Cache] Got history ID:', historyId);

            // Get page content
            let pageContent;
            if (mainWindow && mainWindow.webContents) {
              pageContent = await mainWindow.webContents.executeJavaScript(`
                document.documentElement.outerHTML
              `);
            }
            console.log('[Cache] Got page content, length:', pageContent?.length);
            
            // Cache the page content
            console.log('[Cache] Attempting to cache resource...');
            await cacheManager.cacheResource(details.url, pageContent, historyId);
            console.log('[Cache] Successfully cached page content for:', details.url);
          } catch (innerError) {
            console.error('[Cache] Error inside setTimeout handler:', innerError);
          }
        }, 500);
      } catch (error) {
        console.error('Error setting up page caching:', error);
      }
    }
  });
}

// Add page to history when navigating
function addPageToHistory(url, title, favicon) {
  try {
    // Basic validation - also ignore devtools URLs here
    if (!url || url === 'about:blank' || 
        url.startsWith('chrome://') || 
        url.startsWith('devtools://') || 
        url.startsWith('file://')) {
      return;
    }
    
    // Add to history
    historyManager.addHistory(url, title, favicon);
  } catch (error) {
    console.error('Error adding page to history:', error);
  }
}

// Setup secure webview configuration
function setupWebviewSecurity() {
  app.on('web-contents-created', (event, contents) => {
    if (contents.getType() === 'webview') {
      // Configure webview permissions
      contents.session.setPermissionRequestHandler((webContents, permission, callback) => {
        const allowedPermissions = [
          'downloads',
          'media',
          'notifications',
          'fullscreen',
          'plugins'
        ];
        callback(allowedPermissions.includes(permission));
      });

      // Enable plugins for the webview
      contents.session.setPreloads([path.join(__dirname, 'preload.js')]);
      
      // Handle PDF downloads
      contents.session.on('will-download', (event, item, webContents) => {
        const filePath = path.join(app.getPath('downloads'), item.getFilename());
        item.setSavePath(filePath);
        
        item.on('updated', (event, state) => {
          if (state === 'interrupted') {
            console.log('Download interrupted');
          } else if (state === 'progressing') {
            if (item.isPaused()) {
              console.log('Download paused');
            }
          }
        });
        
        item.once('done', (event, state) => {
          if (state === 'completed') {
            console.log('Download completed');
          } else {
            console.log(`Download failed: ${state}`);
          }
        });
      });
    }
  });
}

// Initialize app when Electron is ready
app.whenReady().then(async () => {
  console.log('Electron app is ready, initializing...');
  
  // API keys are loaded by the Config constructor when config.js is imported.
  // Use the getter to access them.
  const apiKeys = config.getApiKeys(); 
  
  // Debug logging to verify API keys
  console.log('Environment variables loaded:', {
    GSB_KEY_LENGTH: apiKeys.googleSafeBrowsingKey ? apiKeys.googleSafeBrowsingKey.length : 0,
    VT_KEY_LENGTH: apiKeys.virusTotalApiKey ? apiKeys.virusTotalApiKey.length : 0
  });

  // Initialize security modules with API keys
  phishingDetection.setApiKeys(
    apiKeys.googleSafeBrowsingKey,
    apiKeys.virusTotalApiKey
  );

  // Register all IPC handlers BEFORE creating the window
  console.log('Setting up IPC handlers...');
  
  // Navigation handlers
  ipcMain.on('navigate-to', (event, url) => {
    mainWindow?.webContents.send('url-updated', url);
  });

  // Security handlers
  ipcMain.handle('check-phishing', async (event, url) => {
    try {
      // Check if phishing protection is disabled in settings
      if (settings.phishingProtection === false) {
        // Return safe result if phishing protection is disabled
        return { isSafe: true, message: 'Phishing protection is disabled' };
      }
      
      // Otherwise, perform the normal phishing check
      return await phishingDetection.checkUrl(url);
    } catch (error) {
      console.error('Error in phishing check:', error);
      return { isSafe: false, message: 'Error checking URL security' };
    }
  });

  ipcMain.handle('scan-download', async (event, fileInfo) => {
    if (settings.downloadScanning === false) {
      return { isSafe: true, message: 'Download scanning disabled' };
    }
    
    try {
      return await downloadSecurity.scanDownload(fileInfo);
    } catch (error) {
      console.error('Error scanning download:', error);
      return { isSafe: true, message: 'Error during download scan' };
    }
  });

  // Download manager handlers
  ipcMain.on('show-downloads', () => {
    console.log('Show downloads request received');
    downloadManager.showDownloadManager();
  });

  ipcMain.on('clear-downloads', () => {
    downloadManager.clearDownloads();
  });

  // Settings handlers
  ipcMain.handle('get-settings', () => {
    return settings;
  });

  ipcMain.handle('update-settings', async (event, newSettings) => {
    console.log('Updating settings:', newSettings);

    // Remove downloadPath from new settings if present
    if (newSettings.downloadPath) {
      delete newSettings.downloadPath;
    }

    // Update settings object
    settings = { ...settings, ...newSettings };

    // Sync download scanning setting with download manager
    if (newSettings.hasOwnProperty('downloadScanning')) {
      downloadManager.updateSecurityScanning(newSettings.downloadScanning);
    }

    // Save to disk
    store.set('settings', settings); 

    // Notify renderer about updated settings
    mainWindow?.webContents.send('settings-updated', settings);

    // Return updated settings
    return settings;
  });
  
  // API keys handlers
  ipcMain.handle('import-api-keys', async () => {
    // const result = config.importFromEnvFile(); // This function was removed from config.js
    // For now, this handler will just return the currently loaded API keys.
    // If re-importing from a .env file at runtime is needed, config.js needs new methods.
    // if (result) { // Condition removed as importFromEnvFile is commented out
      const apiKeys = config.getApiKeys(); // Get currently loaded keys
      
      phishingDetection.setApiKeys(
        apiKeys.googleSafeBrowsingKey,
        apiKeys.virusTotalApiKey
      );
      
      // downloadSecurity.setApiKey(apiKeys.virusTotalApiKey); // Ensure this is still valid if VT key is used for downloads
      
      return {
        success: true, // Assuming success as we are returning current keys
        googleSafeBrowsingKey: apiKeys.googleSafeBrowsingKey,
        virusTotalApiKey: apiKeys.virusTotalApiKey
      };
    // }
    
    /*
    return { // This part is unreachable if we always return success above
      success: false,
      message: '.env file not found or invalid'
    };
    */
  });
  
  ipcMain.handle('export-api-keys', async () => {
    // const result = config.exportToEnvFile(); // This function was removed from config.js
    // Exporting keys to a .env file from a packaged app is generally not done.
    // If this feature is required, config.js needs new methods.
    return { success: false, message: "Export functionality is currently disabled." };
  });

  // Cache handlers
  ipcMain.handle('clear-cache', async () => {
    console.log('Clearing browser cache...');
    try {
      await cacheManager.clearCache();
      console.log('Cache cleared successfully');
      return true;
    } catch (error) {
      console.error('Error clearing cache:', error);
      return false;
    }
  });
  
  ipcMain.handle('getCacheSize', async () => {
    console.log('Getting cache size...');
    try {
      const size = await cacheManager.getCacheSize();
      console.log('Cache size:', size, 'bytes');
      return size;
    } catch (error) {
      console.error('Error getting cache size:', error);
      return 0;
    }
  });

  // History handlers
  ipcMain.handle('get-history', async (event, limit = 100, offset = 0) => {
    try {
      const history = historyManager.getHistory();
      
      // Apply limit and offset if needed
      if (limit || offset) {
        return history.slice(offset, offset + limit);
      }
      
      return history;
    } catch (error) {
      console.error('Error getting history:', error);
      return [];
    }
  });
  
  ipcMain.handle('get-recent-history', async (event) => {
    try {
      const history = historyManager.getHistory();
      return history.slice(0, 100);
    } catch (error) {
      console.error('Error getting recent history:', error);
      return [];
    }
  });

  ipcMain.handle('search-history', async (event, query) => {
    try {
      const results = historyManager.searchHistory(query);
      return results;
    } catch (error) {
      console.error('Error searching history:', error);
      return [];
    }
  });

  // Handle clearing history with different timeframes
  ipcMain.handle('clear-history', async (event, timeframe) => {
    try {
      const beforeEntries = historyManager.getHistory();
      console.log(`Clearing history, current entries: ${beforeEntries.length}`);
      
      // Clear history
      const historyResult = historyManager.clearHistory();
      
      // Also clear the cache
      console.log('Clearing cache along with history...');
      await cacheManager.clearCache();
      console.log('Cache cleared.');

      const afterEntries = historyManager.getHistory();
      console.log(`After clearing, entries: ${afterEntries.length}`);
      
      return historyResult;
    } catch (error) {
      console.error('Error clearing history and cache:', error);
      return false;
    }
  });

  // Handle deleting individual history entries
  ipcMain.handle('delete-history-entry', async (event, id) => {
    try {
      return historyManager.deleteHistoryEntry(id);
    } catch (error) {
      console.error('Error deleting history entry:', error);
      return false;
    }
  });

  ipcMain.handle('add-history-entry', async (event, entry) => {
    try {
      if (!entry || !entry.url || !entry.title) {
        console.warn('Attempted to add invalid history entry:', entry);
        return null;
      }
      const historyId = await historyManager.addHistoryEntry(
        entry.url,
        entry.title,
        entry.favicon,
        entry.visit_time
      );
      console.log('Added history entry via IPC:', historyId);
      return historyId;
    } catch (error) {
      console.error('Error adding history entry via IPC:', error);
      return null;
    }
  });

  // Create the main window after all handlers are registered
  createWindow();
  setupWebviewSecurity();
  setupHttpsEnforcement();
  setupCaching();
  
  // Clean up orphaned cache files on startup
  try {
    await cacheManager.cleanupCache();
  } catch (err) {
    console.error('Error cleaning up cache:', err);
  }

  // Register the custom protocol for the safe browsing
  protocol.registerFileProtocol('safe', (request, callback) => {
    const url = request.url.substr(7); // Remove 'safe://' from the URL
    callback({ path: path.normalize(`${__dirname}/${url}`) });
  });

  console.log('Initialization complete');
}).catch((error) => {
  console.error('Error during app initialization:', error);
  app.quit(); // Optionally quit the app if initialization fails
});

// Quit when all windows are closed, except on macOS
app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});

// Cleanup on app quit
app.on('will-quit', async () => {
  // await historyManager.close(); // historyManager does not have a close() method
});

ipcMain.on('allow-http-url', (event, url) => {
  allowedHttpUrls.add(url);
  if (mainWindow && mainWindow.webContents) {
    mainWindow.webContents.loadURL(url);
  }
}); 