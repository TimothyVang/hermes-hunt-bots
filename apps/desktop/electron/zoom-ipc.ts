import { BrowserWindow, ipcMain } from 'electron'

import { DEFAULT_ZOOM_LEVEL, percentToZoomLevel, zoomLevelToPercent } from './zoom'

export function registerZoomIpc(setAndPersistZoomLevel: (window: BrowserWindow, zoomLevel: number) => void): void {
  ipcMain.handle('hermes:zoom:get', event => {
    const window = BrowserWindow.fromWebContents(event.sender)
    const level = window && !window.isDestroyed() ? window.webContents.getZoomLevel() : DEFAULT_ZOOM_LEVEL

    return { level, percent: zoomLevelToPercent(level) }
  })

  ipcMain.on('hermes:zoom:set-percent', (event, percent) => {
    const window = BrowserWindow.fromWebContents(event.sender)

    if (!window || window.isDestroyed()) {
      return
    }

    setAndPersistZoomLevel(window, percentToZoomLevel(Number(percent)))
  })
}
