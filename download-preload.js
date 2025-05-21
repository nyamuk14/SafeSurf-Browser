const { contextBridge, ipcRenderer } = require('electron');

// Expose APIs for download manager
contextBridge.exposeInMainWorld('downloadAPI', {
  getDownloads: () => ipcRenderer.invoke('get-downloads'),
  clearDownloads: () => ipcRenderer.send('clear-downloads'),
  showInFolder: (id) => ipcRenderer.send('open-download', id),
  retryDownload: (id) => ipcRenderer.send('retry-download', id),
  cancelDownload: (id) => ipcRenderer.send('cancel-download', id),
  clearDownload: (id) => ipcRenderer.send('clear-download', id),
  
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
  }
}); 