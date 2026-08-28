//go:build windows || darwin || linux

package cmd

import _ "embed"

//go:embed trayicons/tray_icon.ico
var trayIconDisconnected []byte

//go:embed trayicons/tray_icon_connected.ico
var trayIconConnected []byte

//go:embed trayicons/tray_icon_disconnected.ico
var trayIconConnecting []byte

//go:embed trayicons/tray_icon_dark.ico
var trayIconDark []byte
