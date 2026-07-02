package masque

// ConnectUDPPlaneDeselector is implemented by masque endpoints that own a CONNECT-UDP plane.
// Selector outbound should call NotifyConnectUDPPlaneDeselected on the previous member before interrupt.
type ConnectUDPPlaneDeselector interface {
	CloseConnectUDPPlaneOnDeselect()
}

// NotifyConnectUDPPlaneDeselected closes CONNECT-UDP plane state on a deselected outbound (LIFE-3).
func NotifyConnectUDPPlaneDeselected(prev any) {
	if prev == nil {
		return
	}
	if d, ok := prev.(ConnectUDPPlaneDeselector); ok {
		d.CloseConnectUDPPlaneOnDeselect()
	}
}
