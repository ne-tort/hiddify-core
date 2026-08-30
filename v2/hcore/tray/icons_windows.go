//go:build windows

package tray

import _ "embed"

//go:embed icons/tray_icon.ico
var trayIconDisconnected []byte

//go:embed icons/tray_icon_connected.ico
var trayIconConnected []byte

//go:embed icons/tray_icon_disconnected.ico
var trayIconConnecting []byte

//go:embed icons/tray_icon_dark.ico
var trayIconDark []byte
