package stream

import (
	"io"
	"net"

	C "github.com/sagernet/sing-box/constant"
)

// ProdDialShape captures route writer_to / reader_from markers on a CONNECT-stream dial result.
type ProdDialShape struct {
	HasWriterTo         bool
	HasWriterToMarker   bool
	HasReaderFromMarker bool
	OuterTunnelConn     bool
}

// ProdDialShapeOf inspects conn returned from CONNECT-stream dial (CoreSession / Runtime).
func ProdDialShapeOf(conn net.Conn) ProdDialShape {
	var s ProdDialShape
	if conn == nil {
		return s
	}
	_, s.HasWriterTo = conn.(io.WriterTo)
	_, s.HasWriterToMarker = conn.(C.RouteConnectionCopyWriterTo)
	_, s.HasReaderFromMarker = conn.(C.RouteConnectionCopyReaderFrom)
	_, s.OuterTunnelConn = conn.(*TunnelConn)
	return s
}

// OK reports whether conn satisfies the prod route bulk download + upload contract.
func (s ProdDialShape) OK() bool {
	return s.HasWriterTo && s.HasWriterToMarker && s.HasReaderFromMarker && s.OuterTunnelConn
}
