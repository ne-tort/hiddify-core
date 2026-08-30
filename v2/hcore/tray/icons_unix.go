//go:build darwin || linux

package tray

import _ "embed"

//go:embed icons/tray_icon.png
var trayIconDisconnected []byte

//go:embed icons/tray_icon_connected.png
var trayIconConnected []byte

//go:embed icons/tray_icon_disconnected.png
var trayIconConnecting []byte

//go:embed icons/tray_icon_dark.png
var trayIconDark []byte
