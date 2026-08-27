const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { queryOpenAI } = require('./openai-client');

function createWindow() {
  const win = new BrowserWindow({
    width: 900,
    height: 700,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  win.loadFile('index.html');
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

ipcMain.handle('gpt-query', async (event, prompt) => {
  try {
    const text = await queryOpenAI(prompt);
    return { ok: true, text };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});
