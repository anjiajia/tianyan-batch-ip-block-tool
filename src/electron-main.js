import { app, BrowserWindow, shell } from "electron";
import { join } from "node:path";

const port = process.env.PORT || "18787";
process.env.PORT = port;
process.env.TIANYAN_DATA_DIR = join(app.getPath("userData"), "data");

let mainWindow;

async function createWindow() {
  await import("./server.js");

  mainWindow = new BrowserWindow({
    width: 1320,
    height: 880,
    minWidth: 1100,
    minHeight: 720,
    title: "天眼批量封禁工具",
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  await mainWindow.loadURL(`http://127.0.0.1:${port}`);
}

app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
