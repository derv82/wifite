const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  ask: (prompt) => ipcRenderer.invoke('gpt-query', prompt)
});
