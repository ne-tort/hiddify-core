package route

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tlsfragment"
	C "github.com/sagernet/sing-box/constant"
	tmasque "github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

var _ adapter.ConnectionManager = (*ConnectionManager)(nil)

type ConnectionManager struct {
	logger      logger.ContextLogger
	access      sync.Mutex
	connections list.List[io.Closer]
}

func NewConnectionManager(logger logger.ContextLogger) *ConnectionManager {
	return &ConnectionManager{
		logger: logger,
	}
}

func (m *ConnectionManager) Start(stage adapter.StartStage) error {
	return nil
}

func (m *ConnectionManager) Close() error {
	m.access.Lock()
	defer m.access.Unlock()
	for element := m.connections.Front(); element != nil; element = element.Next() {
		common.Close(element.Value)
	}
	m.connections.Init()
	return nil
}

func (m *ConnectionManager) NewConnection(ctx context.Context, this N.Dialer, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	var (
		remoteConn net.Conn
		err        error
	)
	if len(metadata.DestinationAddresses) > 0 || metadata.Destination.IsIP() {
		remoteConn, err = dialer.DialSerialNetwork(ctx, this, N.NetworkTCP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
	} else {
		remoteConn, err = this.DialContext(ctx, N.NetworkTCP, metadata.Destination)
	}
	if err != nil {
		var remoteString string
		if len(metadata.DestinationAddresses) > 0 {
			remoteString = "[" + strings.Join(common.Map(metadata.DestinationAddresses, netip.Addr.String), ",") + "]"
		} else {
			remoteString = metadata.Destination.String()
		}
		var dialerString string
		if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
			dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
			if outbound.Type() == C.TypeBalancer {
				dialerString += "[" + metadata.GetRealOutbound() + "]"
			}
		}
		err = E.Cause(err, "open connection to ", remoteString, dialerString)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		m.logger.ErrorContext(ctx, err)
		return
	}
	err = N.ReportConnHandshakeSuccess(conn, remoteConn)
	if err != nil {
		err = E.Cause(err, "report handshake success")
		remoteConn.Close()
		N.CloseOnHandshakeFailure(conn, onClose, err)
		m.logger.ErrorContext(ctx, err)
		return
	}
	if metadata.TLSFragment || metadata.TLSRecordFragment {
		remoteConn = tf.NewConn(remoteConn, ctx, metadata.TLSFragment, metadata.TLSRecordFragment, metadata.TLSFragmentFallbackDelay)
	}
	m.access.Lock()
	element := m.connections.PushBack(conn)
	m.access.Unlock()
	onClose = N.AppendClose(onClose, func(it error) {
		m.access.Lock()
		defer m.access.Unlock()
		m.connections.Remove(element)
	})
	var done atomic.Bool
	m.preConnectionCopy(ctx, conn, remoteConn, false, &done, onClose)
	m.preConnectionCopy(ctx, remoteConn, conn, true, &done, onClose)
	go m.connectionCopy(ctx, conn, remoteConn, false, &done, onClose)
	go m.connectionCopy(ctx, remoteConn, conn, true, &done, onClose)
}

func (m *ConnectionManager) NewPacketConnection(ctx context.Context, this N.Dialer, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	var (
		remotePacketConn   net.PacketConn
		remoteConn         net.Conn
		destinationAddress netip.Addr
		err                error
	)
	if metadata.UDPConnect {
		parallelDialer, isParallelDialer := this.(dialer.ParallelInterfaceDialer)
		if len(metadata.DestinationAddresses) > 0 {
			if isParallelDialer {
				remoteConn, err = dialer.DialSerialNetwork(ctx, parallelDialer, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
			} else {
				remoteConn, err = N.DialSerial(ctx, this, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses)
			}
		} else if metadata.Destination.IsIP() {
			if isParallelDialer {
				remoteConn, err = dialer.DialSerialNetwork(ctx, parallelDialer, N.NetworkUDP, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
			} else {
				remoteConn, err = this.DialContext(ctx, N.NetworkUDP, metadata.Destination)
			}
		} else {
			remoteConn, err = this.DialContext(ctx, N.NetworkUDP, metadata.Destination)
		}
		if err != nil {
			var remoteString string
			if len(metadata.DestinationAddresses) > 0 {
				remoteString = "[" + strings.Join(common.Map(metadata.DestinationAddresses, netip.Addr.String), ",") + "]"
			} else {
				remoteString = metadata.Destination.String()
			}
			var dialerString string
			if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
				dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
				if outbound.Type() == C.TypeBalancer {
					dialerString += "[" + metadata.GetRealOutbound() + "]"
				}
			}
			err = E.Cause(err, "open packet connection to ", remoteString, dialerString)
			N.CloseOnHandshakeFailure(conn, onClose, err)
			m.logger.ErrorContext(ctx, err)
			return
		}
		remotePacketConn = bufio.NewUnbindPacketConn(remoteConn)
		connRemoteAddr := M.AddrFromNet(remoteConn.RemoteAddr())
		if connRemoteAddr != metadata.Destination.Addr {
			destinationAddress = connRemoteAddr
		}
	} else {
		if len(metadata.DestinationAddresses) > 0 {
			remotePacketConn, destinationAddress, err = dialer.ListenSerialNetworkPacket(ctx, this, metadata.Destination, metadata.DestinationAddresses, metadata.NetworkStrategy, metadata.NetworkType, metadata.FallbackNetworkType, metadata.FallbackDelay)
		} else {
			remotePacketConn, err = this.ListenPacket(ctx, metadata.Destination)
		}
		if err != nil {
			var dialerString string
			if outbound, isOutbound := this.(adapter.Outbound); isOutbound {
				dialerString = " using outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
				if outbound.Type() == C.TypeBalancer {
					dialerString += "[" + metadata.GetRealOutbound() + "]"
				}
			}
			err = E.Cause(err, "listen packet connection using ", dialerString)
			N.CloseOnHandshakeFailure(conn, onClose, err)
			m.logger.ErrorContext(ctx, err)
			return
		}
	}
	err = N.ReportPacketConnHandshakeSuccess(conn, remotePacketConn)
	if err != nil {
		conn.Close()
		remotePacketConn.Close()
		m.logger.ErrorContext(ctx, "report handshake success: ", err)
		return
	}
	if destinationAddress.IsValid() {
		var originDestination M.Socksaddr
		if metadata.RouteOriginalDestination.IsValid() {
			originDestination = metadata.RouteOriginalDestination
		} else {
			originDestination = metadata.Destination
		}
		if natConn, loaded := common.Cast[bufio.NATPacketConn](conn); loaded {
			natConn.UpdateDestination(destinationAddress)
		} else if metadata.Destination != M.SocksaddrFrom(destinationAddress, metadata.Destination.Port) {
			if metadata.UDPDisableDomainUnmapping {
				remotePacketConn = bufio.NewUnidirectionalNATPacketConn(bufio.NewPacketConn(remotePacketConn), M.SocksaddrFrom(destinationAddress, metadata.Destination.Port), originDestination)
			} else {
				remotePacketConn = bufio.NewNATPacketConn(bufio.NewPacketConn(remotePacketConn), M.SocksaddrFrom(destinationAddress, metadata.Destination.Port), originDestination)
			}
		}
	} else if metadata.RouteOriginalDestination.IsValid() && metadata.RouteOriginalDestination != metadata.Destination {
		remotePacketConn = bufio.NewDestinationNATPacketConn(bufio.NewPacketConn(remotePacketConn), metadata.Destination, metadata.RouteOriginalDestination)
	}
	var udpTimeout time.Duration
	if metadata.UDPTimeout > 0 {
		udpTimeout = metadata.UDPTimeout
	} else {
		protocol := metadata.Protocol
		if protocol == "" {
			protocol = C.PortProtocols[metadata.Destination.Port]
		}
		if protocol != "" {
			udpTimeout = C.ProtocolTimeouts[protocol]
		}
	}
	if udpTimeout > 0 {
		ctx, conn = canceler.NewPacketConn(ctx, conn, udpTimeout)
	}
	destination := bufio.NewPacketConn(remotePacketConn)
	m.access.Lock()
	element := m.connections.PushBack(conn)
	m.access.Unlock()
	onClose = N.AppendClose(onClose, func(it error) {
		m.access.Lock()
		defer m.access.Unlock()
		m.connections.Remove(element)
	})
	var done atomic.Bool
	go m.packetConnectionCopy(ctx, conn, destination, false, &done, onClose)
	go m.packetConnectionCopy(ctx, destination, conn, true, &done, onClose)
}

func (m *ConnectionManager) preConnectionCopy(ctx context.Context, source net.Conn, destination net.Conn, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	readHandshake := N.NeedHandshakeForRead(source)
	writeHandshake := N.NeedHandshakeForWrite(destination)
	if readHandshake || writeHandshake {
		var err error
		for {
			err = m.connectionCopyEarlyWrite(source, destination, readHandshake, writeHandshake)
			if err == nil && N.NeedHandshakeForRead(source) {
				continue
			} else if E.IsMulti(err, os.ErrInvalid, context.DeadlineExceeded, io.EOF) {
				err = nil
			}
			break
		}
		if err != nil {
			if !done.Swap(true) {
				onClose(err)
			}
			common.Close(source, destination)
			if !direction {
				m.logger.ErrorContext(ctx, "connection upload handshake: ", err)
			} else {
				m.logger.ErrorContext(ctx, "connection download handshake: ", err)
			}
			return
		}
	}
}

func (m *ConnectionManager) connectionCopy(ctx context.Context, source net.Conn, destination net.Conn, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	var (
		sourceReader      io.Reader = source
		destinationWriter io.Writer = destination
	)
	var readCounters, writeCounters []N.CountFunc
	for {
		sourceReader, readCounters = N.UnwrapCountReader(sourceReader, readCounters)
		destinationWriter, writeCounters = N.UnwrapCountWriter(destinationWriter, writeCounters)
		if cachedSrc, isCached := sourceReader.(N.CachedReader); isCached {
			cachedBuffer := cachedSrc.ReadCached()
			if cachedBuffer != nil {
				dataLen := cachedBuffer.Len()
				_, err := destination.Write(cachedBuffer.Bytes())
				cachedBuffer.Release()
				if err != nil {
					if done.Swap(true) {
						onClose(err)
					}
					common.Close(source, destination)
					if !direction {
						m.logger.ErrorContext(ctx, "connection upload payload: ", err)
					} else {
						m.logger.ErrorContext(ctx, "connection download payload: ", err)
					}
					return
				}
				for _, counter := range readCounters {
					counter(int64(dataLen))
				}
				for _, counter := range writeCounters {
					counter(int64(dataLen))
				}
			}
			continue
		}
		break
	}

	// MASQUE CONNECT-stream streamConn implements io.WriterTo with large HTTP/2/3 body reads; sing
	// bufio.CopyWithCounters only uses ReadBuffer and small sink buffers unless we take WriterTo.
	// It also implements io.ReaderFrom so upload can bulk-read from TUN (parity with std io.Copy).
	// Prefer explicit WriterTo/ReadFrom when advertised: avoids choosing the splice path when a
	// wrapper still exposes syscall.Conn on an inner fd, and keeps MASQUE bulk semantics first.
	_, masqueDownload := source.(interface{ C.RouteConnectionCopyWriterTo })
	_, masqueUpload := destination.(interface{ C.RouteConnectionCopyReaderFrom })
	if masqueDownload || masqueUpload {
		tmasque.TuneConnectStreamTCPRelay(source)
		tmasque.TuneConnectStreamTCPRelay(destination)
	}
	if masqueUpload {
		if tc, ok := source.(net.Conn); ok {
			sourceReader = tmasque.WrapTCPQuickAckReader(tc)
		}
	}
	if masqueDownload {
		if tc, ok := destination.(net.Conn); ok {
			destinationWriter = tmasque.WrapTCPQuickAckWriter(tc, destinationWriter)
		}
	}
	var err error
	var copyHandled bool
	if !copyHandled {
		if wt, ok := sourceReader.(interface {
			io.WriterTo
			C.RouteConnectionCopyWriterTo
		}); ok {
			traceRouteConnectionCopyBranch("writer_to", direction, sourceReader, destinationWriter)
			var written int64
			written, err = wt.WriteTo(destinationWriter)
			if written > 0 {
				for _, counter := range readCounters {
					counter(written)
				}
				for _, counter := range writeCounters {
					counter(written)
				}
			}
			copyHandled = true
		} else if rf, ok := destinationWriter.(interface {
			io.ReaderFrom
			C.RouteConnectionCopyReaderFrom
		}); ok {
			traceRouteConnectionCopyBranch("reader_from", direction, sourceReader, destinationWriter)
			var read int64
			read, err = rf.ReadFrom(sourceReader)
			if read > 0 {
				for _, counter := range readCounters {
					counter(read)
				}
				for _, counter := range writeCounters {
					counter(read)
				}
			}
			copyHandled = true
		}
	}
	if !copyHandled {
		traceRouteConnectionCopyBranch("copy_counters", direction, sourceReader, destinationWriter)
		_, err = bufio.CopyWithCounters(destinationWriter, sourceReader, source, readCounters, writeCounters, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
	}
	if err != nil {
		common.Close(source, destination)
	} else if duplexDst, isDuplex := destination.(N.WriteCloser); isDuplex {
		err = duplexDst.CloseWrite()
		if err != nil {
			common.Close(source, destination)
		}
	} else {
		destination.Close()
	}
	if !done.Swap(true) {
		onClose(err)
	}
	common.Close(source, destination)
	if !direction {
		if err == nil {
			m.logger.DebugContext(ctx, "connection upload finished")
		} else if !E.IsClosedOrCanceled(err) && !strings.Contains(err.Error(), "NO_ERROR") {
			m.logger.ErrorContext(ctx, "connection upload closed: ", err)
		} else {
			m.logger.TraceContext(ctx, "connection upload closed")
		}
	} else {
		if err == nil {
			m.logger.DebugContext(ctx, "connection download finished")
		} else if !E.IsClosedOrCanceled(err) && !strings.Contains(err.Error(), "NO_ERROR") && !strings.Contains(err.Error(), "response body closed") {
			m.logger.ErrorContext(ctx, "connection download closed: ", err)
		} else {
			m.logger.TraceContext(ctx, "connection download closed")
		}
	}
}

func traceRouteConnectionCopyBranch(branch string, direction bool, sourceReader io.Reader, destinationWriter io.Writer) {
	if strings.TrimSpace(os.Getenv("MASQUE_TRACE_COPY")) != "1" {
		return
	}
	dir := "upload"
	if direction {
		dir = "download"
	}
	_, sourceWriterTo := sourceReader.(io.WriterTo)
	_, sourceWriterToMarker := sourceReader.(C.RouteConnectionCopyWriterTo)
	_, destReaderFrom := destinationWriter.(io.ReaderFrom)
	_, destReaderFromMarker := destinationWriter.(C.RouteConnectionCopyReaderFrom)
	fmt.Fprintf(os.Stderr, "MASQUE_COPY branch=%s direction=%s source_type=%T destination_type=%T source_writer_to=%t source_marker=%t destination_reader_from=%t destination_marker=%t\n",
		branch, dir, sourceReader, destinationWriter, sourceWriterTo, sourceWriterToMarker, destReaderFrom, destReaderFromMarker)
}

func (m *ConnectionManager) connectionCopyEarlyWrite(source net.Conn, destination io.Writer, readHandshake bool, writeHandshake bool) error {
	payload := buf.NewPacket()
	defer payload.Release()
	err := source.SetReadDeadline(time.Now().Add(C.ReadPayloadTimeout))
	if err != nil {
		if err == os.ErrInvalid {
			if writeHandshake {
				return common.Error(destination.Write(nil))
			}
		}
		return err
	}
	var (
		isTimeout bool
		isEOF     bool
	)
	_, err = payload.ReadOnceFrom(source)
	if err != nil {
		if E.IsTimeout(err) {
			isTimeout = true
		} else if errors.Is(err, io.EOF) {
			isEOF = true
		} else {
			return E.Cause(err, "read payload")
		}
	}
	_ = source.SetReadDeadline(time.Time{})
	if !payload.IsEmpty() || writeHandshake {
		_, err = destination.Write(payload.Bytes())
		if err != nil {
			return E.Cause(err, "write payload")
		}
	}
	if isTimeout {
		return context.DeadlineExceeded
	} else if isEOF {
		return io.EOF
	}
	return nil
}

func (m *ConnectionManager) packetConnectionCopy(ctx context.Context, source N.PacketReader, destination N.PacketWriter, direction bool, done *atomic.Bool, onClose N.CloseHandlerFunc) {
	var err error
	if direction {
		err = copyPacketDownload(ctx, source, destination)
	} else {
		_, err = bufio.CopyPacket(destination, source)
	}
	if !direction {
		if err == nil {
			m.logger.DebugContext(ctx, "packet upload finished")
		} else if E.IsClosedOrCanceled(err) {
			m.logger.TraceContext(ctx, "packet upload closed")
		} else {
			m.logger.DebugContext(ctx, "packet upload closed: ", err)
		}
	} else {
		if err == nil {
			m.logger.DebugContext(ctx, "packet download finished")
		} else if E.IsClosedOrCanceled(err) {
			m.logger.TraceContext(ctx, "packet download closed")
		} else {
			m.logger.DebugContext(ctx, "packet download closed: ", err)
		}
	}
	if !done.Swap(true) {
		onClose(err)
	}
	common.Close(source, destination)
}

// packetRelayMuxHeadroom is reserved before WritePacket on muxed inbounds (e.g. vmess serverMux)
// that call ExtendHeader on the relay buffer; a full 16 KiB ReadPacket leaves FreeLen()==0 and panics.
const packetRelayMuxHeadroom = 32

// copyPacketDownload relays masque/outbound UDP to the TUN inbound side. CONNECT-UDP and
// CONNECT-IP ICMP port-unreachable (ErrUDPPortUnreachable) must not tear down the relay.
func copyPacketDownload(ctx context.Context, source N.PacketReader, destination N.PacketWriter) error {
	buffer := buf.NewPacket()
	defer buffer.Release()
	for {
		buffer.Reset()
		destinationAddr, err := source.ReadPacket(buffer)
		if err != nil {
			if tmasque.IsUDPPortUnreachable(err) {
				remote := tmasque.UDPPortUnreachableRemote(err, destinationAddr)
				if !remote.IsValid() {
					if pc, ok := destination.(interface{ RemoteAddr() net.Addr }); ok && pc.RemoteAddr() != nil {
						remote = M.SocksaddrFromNet(pc.RemoteAddr()).Unwrap()
					}
				}
				deliverUDPPortUnreachableToTUN(destination, remote)
				continue
			}
			if E.IsClosedOrCanceled(err) {
				return err
			}
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			default:
			}
			return err
		}
		if buffer.IsEmpty() {
			continue
		}
		// Mux inbounds prepend via ExtendHeader (leading space). A full 16 KiB ReadPacket has
		// start==0; cloning with Write() alone leaves no leading space and still panics in vmess mux.
		if buffer.Start() < packetRelayMuxHeadroom || buffer.FreeLen() < packetRelayMuxHeadroom {
			clone := buf.NewPacket()
			payloadLen := buffer.Len()
			clone.Resize(packetRelayMuxHeadroom, payloadLen)
			copy(clone.Bytes(), buffer.Bytes())
			err := destination.WritePacket(clone, destinationAddr)
			clone.Release()
			if err != nil {
				return err
			}
			continue
		}
		if err := destination.WritePacket(buffer, destinationAddr); err != nil {
			return err
		}
	}
}
