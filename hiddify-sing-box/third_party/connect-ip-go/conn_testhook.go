package connectip

// NewConnWithProxiedTestStream constructs a minimal Conn for connectip package unit tests.
func NewConnWithProxiedTestStream(str interface {
	http3Stream
	proxiedIPDatagramCoalescedSender
}) *Conn {
	c := &Conn{str: str}
	c.routeView.Store(&connRouteView{})
	return c
}
