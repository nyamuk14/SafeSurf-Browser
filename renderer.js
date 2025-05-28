// Clean URL helper function
function cleanUrl(url) {
  if (!url) return '';
  try {
    return url.replace(/[^\x20-\x7E]/g, '').trim();
  } catch (error) {
    console.error('Error cleaning URL:', error);
    return url;
  }
}

// Initialize settings
let settings = {};
let currentAlertTimeout;

// Wait for DOM to be fully loaded before initializing
document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const webview = document.getElementById('webview');
  const urlInput = document.getElementById('url-input');
  const goButton = document.getElementById('go-button');
  const backButton = document.getElementById('back-button');
  const forwardButton = document.getElementById('forward-button');
  const refreshButton = document.getElementById('refresh-button');
  const homeButton = document.getElementById('home-button');
  const downloadsButton = document.getElementById('downloads-button');
  const securityIndicator = document.getElementById('security-indicator');
  const securityAlert = document.getElementById('security-alert');
  const alertMessage = document.getElementById('alert-message');
  const dismissAlert = document.getElementById('dismiss-alert');
  const settingsButton = document.getElementById('settings-button');
  const settingsPanel = document.getElementById('settings-panel');
  const saveSettings = document.getElementById('save-settings');
  const closeSettings = document.getElementById('close-settings');

  // Settings elements
  const phishingProtection = document.getElementById('phishing-protection');
  const downloadScanning = document.getElementById('download-scanning');

  // History elements
  const historyPanel = document.getElementById('history-panel');
  const clearHistory = document.getElementById('clear-history');

  // Download panel elements
  const downloadPanel = document.getElementById('download-panel');
  const downloadItemsList = document.getElementById('download-items-list');
  const emptyDownloads = document.getElementById('empty-downloads');
  const closeDownloadPanel = document.getElementById('close-download-panel');
  const clearAllDownloads = document.getElementById('clear-all-downloads');
  const viewAllDownloads = document.getElementById('view-all-downloads');

  // Download panel handling
  let downloads = new Map();

  // Load settings
  async function loadSettings() {
    try {
      // console.log('Loading settings from main process...');
      settings = await window.electronAPI.getSettings();
      // console.log('Settings loaded:', settings);
      
      // Update UI to reflect settings
      phishingProtection.checked = settings.phishingProtection !== false;
      downloadScanning.checked = settings.downloadScanning !== false;
      
      // Load history when settings panel is opened
      loadHistory();
      
      return settings;
    } catch (error) {
      console.error('Error loading settings:', error);
      showSecurityAlert('Error loading settings: ' + error.message, 'warning');
      return {};
    }
  }

  // Show security alerts
  function showSecurityAlert(message, type = 'error') {
    // Clear any existing timeout
    if (currentAlertTimeout) {
      clearTimeout(currentAlertTimeout);
    }

    const alertElement = document.getElementById('security-alert');
    const alertMessage = document.getElementById('alert-message');
    
    alertElement.className = 'security-alert ' + type;
    alertMessage.textContent = message;
    alertElement.classList.remove('hidden');
    
    // Auto-hide after 3 seconds
    currentAlertTimeout = setTimeout(() => {
      alertElement.classList.add('hidden');
    }, 3000);
  }

  // Handle dismiss button click
  document.getElementById('dismiss-alert').addEventListener('click', () => {
    const alertElement = document.getElementById('security-alert');
    alertElement.classList.add('hidden');
    if (currentAlertTimeout) {
      clearTimeout(currentAlertTimeout);
    }
  });

  // Handle URL navigation
  async function navigateToUrl(url) {
    try {
      // Clean the URL first
      url = cleanUrl(url);
      
      // Show loading state
      console.log('Checking URL security:', url);
      console.log('Current phishing protection setting:', settings.phishingProtection);
      
      // Check with security APIs
      const securityCheck = await window.electronAPI.checkPhishing(url);
      console.log('Security check results:', securityCheck);

      if (!securityCheck.isSafe) {
        console.warn('Security warning:', securityCheck.message);
        // Show alert banner and keep the current URL
        showSecurityAlert('🚫 Access Blocked: ' + securityCheck.message, 'error');
        // Keep the blocked URL in the address bar but don't navigate
        urlInput.value = url;
      } else {
        if (securityCheck.message === 'Phishing protection is disabled') {
          console.log('Navigating with phishing protection disabled');
          showSecurityAlert('Warning: Navigating with phishing protection disabled', 'warning');
        } else {
          console.log('URL passed security checks:', securityCheck.message);
        }
        webview.src = url;
      }
    } catch (error) {
      console.error('Navigation error:', error);
      showSecurityAlert('Error checking website security', 'error');
    }
  }

  // Navigation functions
  function navigateTo(url) {
    // Clean up the URL first
    url = cleanUrl(url);
    
    if (url !== '') {
      if (!url.startsWith('http://') && !url.startsWith('https://') && !url.startsWith('file://')) {
        // Check if it's a valid domain
        if (url.includes('.') && !url.includes(' ')) {
          url = 'https://' + url;
        } else {
          // Treat as a search query
          url = 'https://www.google.com/search?q=' + encodeURIComponent(url);
        }
      }
      
      // Update URL input immediately with clean URL
      urlInput.value = url;
      
      // Check if the URL is potentially malicious before navigating
      navigateToUrl(url);
    }
  }

  // Update security indicator based on page security
  function updateSecurityIndicator(isSecure) {
    const iconElement = securityIndicator.querySelector('.material-symbols-rounded');
    
    if (isSecure) {
      securityIndicator.className = 'secure';
      iconElement.textContent = 'lock';
    } else {
      securityIndicator.className = 'insecure';
      iconElement.textContent = 'warning';
    }
  }

  // Event Listeners
  goButton.addEventListener('click', () => {
    navigateTo(urlInput.value);
  });

  urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      navigateTo(urlInput.value);
    }
  });

  backButton.addEventListener('click', () => {
    if (webview.canGoBack()) {
      webview.goBack();
    }
  });

  forwardButton.addEventListener('click', () => {
    if (webview.canGoForward()) {
      webview.goForward();
    }
  });

  refreshButton.addEventListener('click', () => {
    webview.reload();
  });

  homeButton.addEventListener('click', () => {
    navigateTo('https://www.google.com');
  });

  settingsButton.addEventListener('click', async () => {
    console.log('Opening settings panel...');
    settingsPanel.classList.remove('hidden');
    
    try {
      // Show loading state in history list
      const historyList = document.getElementById('history-list');
      historyList.innerHTML = '<div class="loading">Loading browsing history...</div>';
      
      // Load history data
      await loadHistory();
    } catch (error) {
      console.error('Error loading settings data:', error);
      showSecurityAlert('Failed to load history data', 'warning');
    }
  });

  document.getElementById('close-settings').addEventListener('click', () => {
    settingsPanel.classList.add('hidden');
  });

  document.getElementById('save-settings').addEventListener('click', async () => {
    try {
      // Save security settings
      const securitySettings = {
        phishingProtection: document.getElementById('phishing-protection').checked,
        downloadScanning: document.getElementById('download-scanning').checked
      };
      
      console.log('Saving settings:', securitySettings);
      
      // Update settings in main process and wait for response
      const updatedSettings = await window.electronAPI.updateSettings(securitySettings);
      console.log('Settings updated:', updatedSettings);
      
      // Update local settings
      settings = updatedSettings;
      
      // Close the panel
      settingsPanel.classList.add('hidden');
      
      // Show confirmation
      showSecurityAlert('Settings saved successfully', 'success');
    } catch (error) {
      console.error('Error saving settings:', error);
      showSecurityAlert('Error saving settings: ' + error.message, 'error');
    }
  });

  downloadsButton.addEventListener('click', () => {
    // console.log('Downloads button clicked');
    if (window.electronAPI && window.electronAPI.showDownloads) {
      window.electronAPI.showDownloads();
    }
  });

  // Webview events
  webview.addEventListener('did-start-loading', () => {
    document.title = 'Loading... - SafeSurf Browser';
    
    // Update the refresh button to show stop icon
    const refreshIcon = refreshButton.querySelector('.material-symbols-rounded');
    refreshIcon.textContent = 'close';
  });

  // Intercept navigation events to check for phishing
  webview.addEventListener('will-navigate', async (e) => {
    // Check the URL through the phishing detection
    const url = e.url;
    console.log('Intercepted navigation to:', url);
    
    // Only prevent navigation and handle it ourselves if the URL is not safe
    const securityCheck = await window.electronAPI.checkPhishing(url);
    if (!securityCheck.isSafe) {
      e.preventDefault();
      console.warn('Security warning:', securityCheck.message);
      showSecurityAlert('🚫 Access Blocked: ' + securityCheck.message, 'error');
      return;
    }

    // Otherwise let the navigation continue naturally
    console.log('URL passed security checks, continuing navigation');
  });

  // Listen for new window opens (like target="_blank" links)
  webview.addEventListener('new-window', async (e) => {
    // Prevent the default window opening behavior
    e.preventDefault();
    
    console.log('Intercepted popup window request to:', e.url);
    
    // Check if it's from the same origin (more secure)
    const currentUrl = new URL(webview.getURL());
    let targetUrl;
    try {
      targetUrl = new URL(e.url);
    } catch (error) {
      console.error('Invalid URL in popup request:', e.url);
      return;
    }
    
    // Show a notification about the blocked popup
    showSecurityAlert(`Popup blocked: ${targetUrl.hostname}`, 'warning');
    // Navigate to the URL in the same window
    navigateToUrl(e.url);
  });

  webview.addEventListener('did-finish-load', async () => {
    // Update UI elements
    urlInput.value = webview.getURL();
    document.title = webview.getTitle() + ' - SafeSurf Browser';
    updateSecurityIndicator(webview.getURL().startsWith('https://'));
    
    // Restore refresh icon
    const refreshIcon = refreshButton.querySelector('.material-symbols-rounded');
    refreshIcon.textContent = 'refresh';
    
    // Update navigation buttons state
    updateNavigationButtons();
    
    const currentUrl = cleanUrl(webview.getURL());
    const currentTitle = webview.getTitle() || 'Untitled';
    
    if (!currentUrl || currentUrl === 'about:blank') {
      return; // Don't record empty or about:blank pages
    }
    
    try {
      // This might get a better page title after the page has fully loaded
      const entry = {
        url: currentUrl,
        title: currentTitle,
        favicon: null,
        visit_time: Date.now()
      };
      
      // Only add if URL is different than what's in input field (avoid duplicates)
      try {
        const result = await window.electronAPI.addHistoryEntry(entry);
      } catch (ipcError) {
        console.error('Failed to add history via IPC:', ipcError);
      }
      
      // Reload history if the panel is open
      if (!settingsPanel.classList.contains('hidden')) {
        loadHistory();
      }
    } catch (error) {
      console.error('Error in did-finish-load event handler:', error);
    }
  });

  webview.addEventListener('did-fail-load', (e) => {
    // Don't show error for aborted loads (like when user navigates away)
    if (e.errorCode !== -3) {
      showSecurityAlert(`Page failed to load: ${e.errorDescription}`, 'warning');
    }
    
    // Restore refresh icon
    const refreshIcon = refreshButton.querySelector('.material-symbols-rounded');
    refreshIcon.textContent = 'refresh';
  });

  webview.addEventListener('page-title-updated', (e) => {
    document.title = e.title + ' - SafeSurf Browser';
  });

  webview.addEventListener('did-navigate', async (e) => {
    // Clean up the URL before displaying
    const currentUrl = cleanUrl(e.url);
    urlInput.value = currentUrl;
    updateSecurityIndicator(currentUrl.startsWith('https://'));
    updateNavigationButtons();
    
    if (!currentUrl || currentUrl === 'about:blank') {
      return; // Don't record empty or about:blank pages
    }
    
    try {
      // Add the page to history immediately with current title
      const title = webview.getTitle() || 'Untitled';
      
      // Add page to history
      const entry = {
        url: currentUrl,
        title: title,
        favicon: null, // Don't try to guess favicon URL - it causes errors
        visit_time: Date.now()
      };
      
      // Use a try-catch specifically around the ipc call
      try {
        const result = await window.electronAPI.addHistoryEntry(entry);
      } catch (ipcError) {
        console.error('Failed to add history via IPC:', ipcError);
      }
      
      // Reload history if the panel is open
      if (!settingsPanel.classList.contains('hidden')) {
        loadHistory();
      }
    } catch (error) {
      console.error('Error in did-navigate event handler:', error);
    }
  });

  webview.addEventListener('did-navigate-in-page', () => {
    updateNavigationButtons();
  });

  webview.addEventListener('ipc-message', (e) => {
    if (e.channel === 'security-warning') {
      showSecurityAlert(e.args[0].message);
    }
  });

  // Listen for updates from the main process
  window.electronAPI.onURLUpdate((event, url) => {
    urlInput.value = url;
    updateSecurityIndicator(url.startsWith('https://'));
  });

  window.electronAPI.onSecurityAlert((event, message) => {
    // Determine alert type based on message content
    let alertType = 'danger';
    if (message.toLowerCase().includes('success')) {
      alertType = 'success';
    } else if (message.toLowerCase().includes('warning')) {
      alertType = 'warning';
    }
    
    showSecurityAlert(message, alertType);
  });

  // Listen for settings updates from main process
  window.electronAPI.onSettingsUpdated((event, updatedSettings) => {
    console.log('Settings updated from main process:', updatedSettings);
    settings = updatedSettings;
  });

  // Update navigation buttons based on webview state
  function updateNavigationButtons() {
    backButton.disabled = !webview.canGoBack();
    forwardButton.disabled = !webview.canGoForward();
    
    if (backButton.disabled) {
      backButton.classList.add('disabled');
    } else {
      backButton.classList.remove('disabled');
    }
    
    if (forwardButton.disabled) {
      forwardButton.classList.add('disabled');
    } else {
      forwardButton.classList.remove('disabled');
    }
  }

  // Load and display history
  async function loadHistory() {
    try {
      // console.log('Loading history...');
      const historyList = document.getElementById('history-list');
      
      // Get history from main process
      const history = await window.electronAPI.getHistory();
      // console.log(`Loaded ${history?.length || 0} history entries`);
      
      // Display history entries
      if (Array.isArray(history) && history.length > 0) {
        // Sort by visit time (newest first)
        // The visitTime is now an ISO string, so we parse it to Date objects
        history.sort((a, b) => new Date(b.visitTime) - new Date(a.visitTime));
        
        // Generate HTML for history items
        let historyHTML = '';
        
        history.forEach(entry => {
          const formattedTime = formatDate(entry.visitTime);
          
          historyHTML += `
          <div class="history-item" data-url="${entry.url}" data-id="${entry.id}">
            <img class="favicon" src="${entry.favicon || ''}" onerror="this.style.display='none'">
            <div class="content">
              <div class="title">${entry.title || 'No Title'}</div>
              <div class="url">${entry.url}</div>
              <div class="time">${formattedTime}</div>
            </div>
          </div>`;
        });
        
        historyList.innerHTML = historyHTML;
        
        // Add click event to history items
        document.querySelectorAll('.history-item').forEach(item => {
          item.addEventListener('click', () => {
            const url = item.getAttribute('data-url');
            navigateTo(url);
          });
        });
      } else {
        // Show empty history message
        historyList.innerHTML = `
        <div class="empty-history">
          <p>No browsing history</p>
          <span>Your browsing history will appear here</span>
        </div>`;
      }
    } catch (error) {
      console.error('Error loading history:', error);
      const historyList = document.getElementById('history-list');
      historyList.innerHTML = `
        <div class="empty-history">
          <p>Could not load history</p>
          <span id="history-error-message"></span>
        </div>`;
      document.getElementById('history-error-message').textContent = error.message || 'Unknown error';
    }
  }

  // Format date for history entries
  function formatDate(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;
    
    // Less than a minute
    if (diff < 60000) {
      return 'Just now';
    }
    
    // Less than an hour
    if (diff < 3600000) {
      const minutes = Math.floor(diff / 60000);
      return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    }
    
    // Less than a day
    if (diff < 86400000) {
      const hours = Math.floor(diff / 3600000);
      return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    }
    
    // Less than a week
    if (diff < 604800000) {
      const days = Math.floor(diff / 86400000);
      return `${days} day${days > 1 ? 's' : ''} ago`;
    }
    
    // Format as a date
    return date.toLocaleDateString();
  }

  // Clear history with confirmation
  document.getElementById('clear-history').addEventListener('click', async () => {
    console.log('Clear history button clicked');
    
    try {
      const confirmed = confirm('Are you sure you want to clear all browsing history and cache? This action cannot be undone.');
      
      if (!confirmed) {
        console.log('User cancelled clearing history and cache');
        return;
      }
      
      console.log('User confirmed clearing history and cache');
      
      // Show loading state
      const historyList = document.getElementById('history-list');
      historyList.innerHTML = '<div class="loading">Clearing history and cache...</div>';
      
      // Show alert
      showSecurityAlert('Clearing browsing history and cache...', 'warning');
      
      // Clear history via IPC - with improved error handling
      try {
        console.log('Sending clear-history request to main process');
        const result = await window.electronAPI.clearHistory();
        console.log('Clear history result:', result);
        
        // Show empty history UI
        historyList.innerHTML = `
        <div class="empty-history">
          <p>No browsing history</p>
          <span>Your browsing history and cache have been cleared</span>
        </div>`;
        
        showSecurityAlert('Browsing history and cache cleared successfully', 'success');
      } catch (error) {
        console.error('Error clearing history and cache:', error);
        showSecurityAlert('Error clearing history and cache: ' + error.message, 'error');
        
        // Try to reload history anyway
        loadHistory().catch(e => console.error('Error reloading history:', e));
      }
    } catch (outerError) {
      console.error('Unexpected error in clear history handler:', outerError);
    }
  });

  // Update cache size display
  async function updateCacheSize() {
    try {
      const cacheSizeElement = document.getElementById('cache-size');
      if (!cacheSizeElement) {
        console.error('Cache size element not found');
        return;
      }
      
      cacheSizeElement.textContent = 'Calculating cache size...';
      
      console.log('Requesting cache size...');
      const cacheSize = await window.electronAPI.getCacheSize();
      console.log('Received cache size:', cacheSize);
      
      // Format size nicely
      if (cacheSize === 0) {
        cacheSizeElement.textContent = 'Cache is empty';
      } else if (cacheSize < 1024) {
        cacheSizeElement.textContent = `Cache size: ${cacheSize} B`;
      } else if (cacheSize < 1024 * 1024) {
        cacheSizeElement.textContent = `Cache size: ${(cacheSize / 1024).toFixed(1)} KB`;
      } else if (cacheSize < 1024 * 1024 * 1024) {
        cacheSizeElement.textContent = `Cache size: ${(cacheSize / (1024 * 1024)).toFixed(1)} MB`;
      } else {
        cacheSizeElement.textContent = `Cache size: ${(cacheSize / (1024 * 1024 * 1024)).toFixed(2)} GB`;
      }
    } catch (error) {
      console.error('Error getting cache size:', error);
      const cacheSizeElement = document.getElementById('cache-size');
      if (cacheSizeElement) {
        cacheSizeElement.textContent = 'Cache size unavailable';
      }
    }
  }

  // Format file size nicely
  function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }
  
  // Format time remaining
  function formatTimeRemaining(seconds) {
    if (!seconds || seconds < 0) return '';
    if (seconds < 60) return `${Math.ceil(seconds)}s remaining`;
    if (seconds < 3600) {
      const mins = Math.floor(seconds / 60);
      return `${mins} min${mins > 1 ? 's' : ''} remaining`;
    }
    const hours = Math.floor(seconds / 3600);
    return `${hours} hour${hours > 1 ? 's' : ''} remaining`;
  }
  
  // Get file type icon
  function getFileTypeIcon(fileName) {
    if (!fileName) return 'file_present';
    const extension = fileName.split('.').pop().toLowerCase();
    
    const iconMap = {
      // Documents
      'pdf': 'picture_as_pdf',
      'doc': 'description',
      'docx': 'description',
      'txt': 'description',
      // Images
      'jpg': 'image',
      'jpeg': 'image',
      'png': 'image',
      'gif': 'image',
      'webp': 'image',
      // Audio/Video
      'mp3': 'audio_file',
      'mp4': 'video_file',
      'avi': 'video_file',
      'mov': 'video_file',
      // Archives
      'zip': 'folder_zip',
      'rar': 'folder_zip',
      // Executables
      'exe': 'warning',
      'msi': 'warning',
    };
    
    return iconMap[extension] || 'file_present';
  }
  
  // Create or update download item in panel
  function createOrUpdateDownloadItem(download) {
    let item = document.getElementById(`download-item-${download.id}`);
    
    if (!item) {
      // Create new item
      item = document.createElement('li');
      item.className = 'download-item';
      item.id = `download-item-${download.id}`;
      downloadItemsList.prepend(item); // Add to top of list
    }
    
    // Update item content
    const fileIcon = getFileTypeIcon(download.fileName);
    let progressHtml = '';
    
    if (['downloading', 'progressing'].includes(download.state)) {
      const progress = download.totalBytes > 0 
        ? Math.round((download.receivedBytes / download.totalBytes) * 100) 
        : 0;
      
      progressHtml = `
        <div class="download-progress">
          <div class="download-progress-bar" style="width: ${progress}%"></div>
        </div>
      `;
    }
    
    // Generate status text
    let statusText = '';
    let detailsText = '';
    
    switch (download.state) {
      case 'downloading':
      case 'progressing':
        if (download.totalBytes > 0) {
          const progress = Math.round((download.receivedBytes / download.totalBytes) * 100);
          statusText = `${progress}% complete`;
          
          if (download.speed) {
            const formattedSize = formatFileSize(download.receivedBytes);
            const totalSize = formatFileSize(download.totalBytes);
            detailsText = `${formattedSize} of ${totalSize}`;
            
            if (download.remainingTime) {
              detailsText += ` · ${formatTimeRemaining(download.remainingTime)}`;
            }
          }
        } else {
          statusText = 'Downloading...';
          if (download.receivedBytes > 0) {
            detailsText = formatFileSize(download.receivedBytes);
          }
        }
        break;
      case 'completed':
        statusText = 'Done';
        if (download.totalBytes > 0) {
          detailsText = formatFileSize(download.totalBytes);
        }
        break;
      case 'blocked':
        statusText = 'Blocked - Security Risk';
        detailsText = download.securityInfo || 'This file was blocked for security reasons';
        item.classList.add('download-blocked');
        break;
      case 'malicious':
        statusText = 'Security Risk Detected';
        if (download.securityScanResult) {
          detailsText = download.securityScanResult.message;
        }
        item.classList.add('download-malicious');
        break;
      case 'interrupted':
        statusText = 'Download interrupted';
        break;
      case 'cancelled':
        statusText = 'Download cancelled';
        break;
      case 'failed':
        statusText = 'Failed';
        break;
      default:
        statusText = download.state;
    }
    
    // Generate action buttons
    let actions = '';
    
    if (download.state === 'completed') {
      actions = `
        <button class="download-action" onclick="window.downloadAPI.clearDownload('${download.id}')" title="Remove from list">
          <span class="material-symbols-rounded">close</span>
        </button>
      `;
    } else if (['downloading', 'progressing'].includes(download.state)) {
      actions = `
        <button class="download-action" onclick="window.downloadAPI.cancelDownload('${download.id}')" title="Cancel">
          <span class="material-symbols-rounded">close</span>
        </button>
      `;
    } else if (['interrupted', 'cancelled', 'failed'].includes(download.state)) {
      actions = `
        <button class="download-action" onclick="window.downloadAPI.retryDownload('${download.id}')" title="Retry">
          <span class="material-symbols-rounded">refresh</span>
        </button>
        <button class="download-action" onclick="window.downloadAPI.clearDownload('${download.id}')" title="Remove from list">
          <span class="material-symbols-rounded">close</span>
        </button>
      `;
    } else if (['blocked', 'malicious'].includes(download.state)) {
      actions = `
        <button class="download-action" onclick="window.downloadAPI.clearDownload('${download.id}')" title="Remove from list">
          <span class="material-symbols-rounded">close</span>
        </button>
      `;
    }
    
    // Add security icons for blocked or malicious downloads
    let securityIcon = '';
    if (download.state === 'blocked' || download.state === 'malicious') {
      securityIcon = `<span class="security-icon material-symbols-rounded">security</span>`;
    }
    
    // Set the HTML content with appropriate classes for security states
    let itemClass = 'download-item';
    if (download.state === 'blocked') itemClass += ' download-blocked';
    if (download.state === 'malicious') itemClass += ' download-malicious';
    
    item.className = itemClass;
    
    item.innerHTML = `
      <div class="download-icon">
        <span class="material-symbols-rounded">${fileIcon}</span>
        ${securityIcon}
      </div>
      <div class="download-info">
        <div class="download-filename">${download.fileName}</div>
        <div class="download-status">${statusText}</div>
        ${detailsText ? `<div class="download-details">${detailsText}</div>` : ''}
        ${progressHtml}
      </div>
      <div class="download-actions">
        ${actions}
      </div>
    `;
    
    // Update empty state display
    updateEmptyState();
  }
  
  // Handle download events
  function setupDownloadHandlers() {
    // Toggle download panel
    downloadsButton.addEventListener('click', () => {
      // console.log('Downloads button clicked');
      if (window.electronAPI && window.electronAPI.showDownloads) {
        window.electronAPI.showDownloads();
      }
    });
    
    // Close download panel
    closeDownloadPanel.addEventListener('click', () => {
      downloadPanel.style.display = 'none';
      window.downloadAPI.closeDownloadPanel();
    });
    
    // Clear all downloads
    clearAllDownloads.addEventListener('click', () => {
      if (downloads.size === 0) return;
      
      const confirmed = confirm('Clear all downloads from list?');
      if (confirmed) {
        window.downloadAPI.clearDownloads();
        downloads.clear();
        downloadItemsList.innerHTML = '';
        updateEmptyState();
      }
    });
    
    // Listen for download panel toggle
    window.downloadAPI.onToggleDownloadPanel((data) => {
      // console.log('Toggle download panel:', data);
      if (data.isVisible) {
        downloadPanel.style.display = 'flex';
        // Refresh downloads list
        if (data.downloads && Array.isArray(data.downloads)) {
          // Clear existing downloads
          downloadItemsList.innerHTML = '';
          downloads.clear();
          
          // Add new downloads
          data.downloads.forEach(download => {
            downloads.set(download.id, download);
            createOrUpdateDownloadItem(download);
          });
          
          updateEmptyState();
        }
      } else {
        downloadPanel.style.display = 'none';
      }
    });
    
    // Listen for new downloads
    window.downloadAPI.onDownloadStarted((download) => {
      console.log('New download:', download.fileName);
      downloads.set(download.id, download);
      createOrUpdateDownloadItem(download);
    });
    
    // Listen for download updates
    window.downloadAPI.onDownloadUpdated((download) => {
      downloads.set(download.id, download);
      createOrUpdateDownloadItem(download);
    });
    
    // Listen for download removals
    window.downloadAPI.onDownloadRemoved((id) => {
      downloads.delete(id);
      const item = document.getElementById(`download-item-${id}`);
      if (item) {
        item.remove();
      }
      updateEmptyState();
    });
    
    // Listen for downloads cleared
    window.downloadAPI.onDownloadsCleared(() => {
      downloads.clear();
      downloadItemsList.innerHTML = '';
      updateEmptyState();
    });
  }
  
  // Update empty state display
  function updateEmptyState() {
    if (downloads.size === 0) {
      emptyDownloads.style.display = 'block';
      downloadItemsList.style.display = 'none';
    } else {
      emptyDownloads.style.display = 'none';
      downloadItemsList.style.display = 'block';
    }
  }

  // Initialize download panel
  setupDownloadHandlers();

  // Initialize
  loadSettings().then(() => {
    // Update URL input with initial URL
    urlInput.value = webview.getURL() || 'https://www.google.com';
    
    // If webview failed to load initial URL, navigate to Google
    if (webview.getURL() === 'about:blank') {
      navigateTo('https://www.google.com');
    }

    // Initialize downloads (fetch existing downloads)
    window.downloadAPI.getDownloads().then(downloadList => {
      if (Array.isArray(downloadList) && downloadList.length > 0) {
        downloadList.forEach(download => {
          downloads.set(download.id, download);
          createOrUpdateDownloadItem(download);
        });
        updateEmptyState();
      } else {
        updateEmptyState();
      }
    }).catch(error => {
      console.error('Error fetching downloads:', error);
    });
  }).catch(error => {
    console.error('Error during renderer initialization:', error);
  });

  // Add detection for link clicks to check URLs through phishing detection
  webview.addEventListener('dom-ready', () => {
    // Update URL and security indicator when webview is ready
    const currentUrl = webview.getURL();
    urlInput.value = currentUrl;
    updateSecurityIndicator(currentUrl.startsWith('https://'));
    
    // Set a standard user agent for the webview to avoid detection issues
    webview.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36');
    
    // Inject script to intercept link clicks
    webview.executeJavaScript(`
      // Only set up once per page
      if (!window._safeSurfLinkHandler) {
        window._safeSurfLinkHandler = true;
        
        // We don't need to intercept normal link clicks anymore
        // The links will naturally trigger navigation events or new-window events
        // which our event handlers will process
        
        true; // Return value for executeJavaScript
      }
    `);
    
    // If still on about:blank after dom-ready, navigate to Google
    if (currentUrl === 'about:blank') {
      navigateTo('https://www.google.com');
    }
  });

  // Handle downloads
  webview.addEventListener('will-download', (event, item) => {
    console.log('Download started:', item);
    
    // We don't need to handle download tracking here
    // The download-manager.js in the main process will track all downloads
    // This is captured by the session.on('will-download') handler in main process
    
    // The main process will:
    // 1. Set the save path
    // 2. Track progress 
    // 3. Handle completion
    // 4. Notify the renderer via IPC
    
    console.log('Download will be handled by the main process');
  });

  // Add keyboard shortcut (Alt+D) for test downloads
  document.addEventListener('keydown', (e) => {
    if (e.altKey && e.key === 'd') {
      console.log('Test download triggered via keyboard shortcut (Alt+D)');
      window.electronAPI.testDownload();
    }
  });

  window.electronAPI.onHttpBlocked(({ url }) => {
    showSecurityAlert(
      `This site is not secure (HTTP). <button id="continue-anyway">Continue Anyway</button>`,
      'error'
    );
    setTimeout(() => {
      const btn = document.getElementById('continue-anyway');
      if (btn) {
        btn.onclick = () => {
          window.electronAPI.allowHttpUrl(url);
        };
      }
    }, 0);
  });
}); 