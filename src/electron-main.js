import electron from "electron";
import electronUpdater from "electron-updater";
import { join } from "node:path";

const { app, BrowserWindow, dialog, shell } = electron;
const { autoUpdater } = electronUpdater;
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
    title: "\u5929\u773c\u6279\u91cf\u5c01\u7981\u5de5\u5177",
    icon: join(app.getAppPath(), "build", "icons", process.platform === "win32" ? "icon.ico" : "icon.png"),
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
  configureAutoUpdate();
}

app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

function configureAutoUpdate() {
  if (!app.isPackaged) return;

  autoUpdater.autoDownload = false;
  autoUpdater.on("update-available", async (info) => {
    const result = await dialog.showMessageBox(mainWindow, {
      type: "info",
      buttons: ["\u4e0b\u8f7d\u66f4\u65b0", "\u7a0d\u540e"],
      defaultId: 0,
      cancelId: 1,
      title: "\u53d1\u73b0\u65b0\u7248\u672c",
      message: `\u53d1\u73b0\u65b0\u7248\u672c ${info.version}\uff0c\u662f\u5426\u73b0\u5728\u4e0b\u8f7d\uff1f`,
    });
    if (result.response === 0) autoUpdater.downloadUpdate();
  });

  autoUpdater.on("update-downloaded", async () => {
    const result = await dialog.showMessageBox(mainWindow, {
      type: "info",
      buttons: ["\u91cd\u542f\u5b89\u88c5", "\u7a0d\u540e"],
      defaultId: 0,
      cancelId: 1,
      title: "\u66f4\u65b0\u5df2\u4e0b\u8f7d",
      message: "\u65b0\u7248\u672c\u5df2\u4e0b\u8f7d\u5b8c\u6210\uff0c\u91cd\u542f\u540e\u5b89\u88c5\u66f4\u65b0\u3002",
    });
    if (result.response === 0) autoUpdater.quitAndInstall();
  });

  autoUpdater.on("error", (error) => {
    console.error("Auto update failed:", error);
  });

  setTimeout(() => {
    autoUpdater.checkForUpdates().catch((error) => {
      console.error("Update check failed:", error);
    });
  }, 5000);
}
