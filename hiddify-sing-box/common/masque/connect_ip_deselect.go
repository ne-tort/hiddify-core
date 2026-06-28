package masque

// ConnectIPPlaneDeselector is implemented by masque endpoints that own an eager CONNECT-IP plane.
// Selector outbound should call NotifyConnectIPPlaneDeselected on the previous member before interrupt.
type ConnectIPPlaneDeselector interface {
	CloseConnectIPPlaneOnDeselect()
}

// NotifyConnectIPPlaneDeselected closes CONNECT-IP plane state on a deselected outbound (LIFE-3).
func NotifyConnectIPPlaneDeselected(prev any) {
	if prev == nil {
		return
	}
	if d, ok := prev.(ConnectIPPlaneDeselector); ok {
		d.CloseConnectIPPlaneOnDeselect()
	}
}
