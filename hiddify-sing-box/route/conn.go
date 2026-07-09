package route

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
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
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
	"github.com/sagernet/sing/common/x/list"
)

// connectionCopyGate defers onClose until all relay copy legs finish (MASQUE probe→bulk).
type connectionCopyGate struct {
	remaining   atomic.Int32
	closed      atomic.Bool
	relayBytes  atomic.Int64
	uploadBytes atomic.Int64
}

const connectIPShortRelayWarmThreshold = 256 * 1024
const connectIPShortRelayUploadWarmMax = 8 * 1024

// connectionCopyRelayStallTimeout aborts relay when no bytes move while legs remain open.
const connectionCopyRelayStallTimeout = 5 * time.Second

// connectionCopyRelayZeroByteTimeout aborts relay that never transferred bytes (ghost stream / stuck dial).
const connectionCopyRelayZeroByteTimeout = 10 * time.Second

const connectionCopyRelayStallPoll = 500 * time.Millisecond

func newConnectionCopyGate(legs int32) *connectionCopyGate {
	g := &connectionCopyGate{}
	g.remaining.Store(legs)
	return g
}

func (g *connectionCopyGate) addRelayBytes(upload bool, n int64) {
	if n <= 0 {
		return
	}
	g.relayBytes.Add(n)
	if upload {
		g.uploadBytes.Add(n)
	}
}

func (g *connectionCopyGate) finish(onClose N.CloseHandlerFunc, err error) {
	if g.remaining.Add(-1) == 0 && !g.closed.Swap(true) {
		onClose(err)
	}
}

func (g *connectionCopyGate) abort(onClose N.CloseHandlerFunc, err error) {
	if g.remaining.Swap(0) > 0 && !g.closed.Swap(true) {
		onClose(err)
	}
}

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
	dest := metadata.Destination
	dialer := this
	copyGate := newConnectionCopyGate(2)
	onClose = N.AppendClose(onClose, func(it error) {
		m.access.Lock()
		defer m.access.Unlock()
		m.connections.Remove(element)
		if copyGate.relayBytes.Load() >= connectIPShortRelayWarmThreshold ||
			copyGate.uploadBytes.Load() >= connectIPShortRelayUploadWarmMax {
			return
		}
		nativeL3 := false
		if probe, ok := dialer.(interface{ ConnectIPNativeL3Active() bool }); ok {
			nativeL3 = probe.ConnectIPNativeL3Active()
		}
		if !nativeL3 {
			if resetter, ok := dialer.(interface {
				ResetConnectIPTCPAfterShortRelay()
			}); ok {
				resetter.ResetConnectIPTCPAfterShortRelay()
			}
			if w, ok := dialer.(interface {
				WarmConnectIPTCPAfterShortRelay(context.Context, M.Socksaddr)
			}); ok && dest.IsValid() {
				go func(d M.Socksaddr) {
					time.Sleep(200 * time.Millisecond)
					warmCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					w.WarmConnectIPTCPAfterShortRelay(warmCtx, d)
					cancel()
				}(dest)
			}
		}
	})
	markConnectionCopyDuplex(conn)
	markConnectionCopyDuplex(remoteConn)
	m.preConnectionCopy(ctx, conn, remoteConn, false, copyGate, onClose)
	m.preConnectionCopy(ctx, remoteConn, conn, true, copyGate, onClose)
	// Download copy first so MASQUE CONNECT-stream WriteTo can deliver server banner
	// before upload ReadFrom blocks on SOCKS clients waiting for that banner (iperf -R).
	go m.connectionCopy(ctx, remoteConn, conn, true, copyGate, onClose)
	go m.connectionCopy(ctx, conn, remoteConn, false, copyGate, onClose)
	go m.connectionCopyRelayStallWatchdog(copyGate, onClose, conn, remoteConn)
}

func markConnectionCopyDuplex(conn net.Conn) {
	if conn == nil {
		return
	}
	if d, ok := conn.(C.RouteConnectionCopyDuplex); ok {
		d.MarkConnectionCopyDuplex()
	}
}

func (m *ConnectionManager) connectionCopyRelayStallWatchdog(gate *connectionCopyGate, onClose N.CloseHandlerFunc, a, b net.Conn) {
	ticker := time.NewTicker(connectionCopyRelayStallPoll)
	defer ticker.Stop()
	var lastBytes int64
	stallDeadline := time.Now().Add(connectionCopyRelayStallTimeout)
	zeroByteDeadline := time.Now().Add(connectionCopyRelayZeroByteTimeout)
	var sawRelay bool
	for range ticker.C {
		if gate.closed.Load() || gate.remaining.Load() == 0 {
			return
		}
		cur := gate.relayBytes.Load()
		if cur > 0 {
			sawRelay = true
		}
		if !sawRelay {
			if time.Now().After(zeroByteDeadline) {
				m.abortRelayWatchdog(gate, onClose, a, b, "route relay watchdog zero-byte", cur)
				return
			}
			continue
		}
		if cur > lastBytes {
			lastBytes = cur
			stallDeadline = time.Now().Add(connectionCopyRelayStallTimeout)
			continue
		}
		if time.Now().After(stallDeadline) {
			m.abortRelayWatchdog(gate, onClose, a, b, "route relay watchdog stall", cur)
			return
		}
	}
}

func (m *ConnectionManager) abortRelayWatchdog(gate *connectionCopyGate, onClose N.CloseHandlerFunc, a, b net.Conn, phase string, relayBytes int64) {
	log.Printf("masque_route_relay_watchdog phase=%s relay_bytes=%d upload_bytes=%d",
		phase, relayBytes, gate.uploadBytes.Load())
	gate.abort(onClose, fmt.Errorf("%s: %w", phase, context.DeadlineExceeded))
	pokeRelayDeadlines(a, b)
	common.Close(a, b)
}

func pokeRelayDeadlines(conns ...net.Conn) {
	now := time.Now()
	for _, c := range conns {
		if c == nil {
			continue
		}
		_ = c.SetReadDeadline(now)
		_ = c.SetWriteDeadline(now)
	}
}

func (m *ConnectionManager) NewPacketConnection(ctx context.Context, this N.Dialer, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = adapter.WithContext(ctx, &metadata)
	var tunUpload *tunPacketUploadRelay
	if nc, ok := conn.(udpnat.Conn); ok {
		tunUpload = &tunPacketUploadRelay{}
		nc.SetHandler(tunUpload)
	}
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
	tuneUDPPacketConn(conn)
	tuneUDPPacketConn(remotePacketConn)
	destination := bufio.NewPacketConn(remotePacketConn)
	if tunUpload != nil {
		tunUpload.attach(destination)
		onClose = N.AppendClose(onClose, func(error) { tunUpload.flush() })
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
	if tunUpload == nil {
		go m.packetConnectionCopy(ctx, conn, destination, false, &done, onClose)
	}
	go m.packetConnectionCopy(ctx, destination, conn, true, &done, onClose)
}

func (m *ConnectionManager) preConnectionCopy(ctx context.Context, source net.Conn, destination net.Conn, direction bool, gate *connectionCopyGate, onClose N.CloseHandlerFunc) {
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
			gate.abort(onClose, err)
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

func (m *ConnectionManager) connectionCopy(ctx context.Context, source net.Conn, destination net.Conn, direction bool, gate *connectionCopyGate, onClose N.CloseHandlerFunc) {
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
					gate.finish(onClose, err)
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
				gate.addRelayBytes(!direction, int64(dataLen))
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
	branch := selectConnectionCopyBranch(sourceReader, destinationWriter)
	traceRouteConnectionCopyBranch(string(branch), direction, sourceReader, destinationWriter)
	var err error
	switch branch {
	case connectionCopyBranchWriterTo:
		wt := sourceReader.(interface {
			io.WriterTo
			C.RouteConnectionCopyWriterTo
		})
		var written int64
		written, err = wt.WriteTo(destinationWriter)
		if written > 0 {
			for _, counter := range readCounters {
				counter(written)
			}
			for _, counter := range writeCounters {
				counter(written)
			}
			gate.addRelayBytes(!direction, written)
		}
	case connectionCopyBranchReaderFrom:
		rf := destinationWriter.(interface {
			io.ReaderFrom
			C.RouteConnectionCopyReaderFrom
		})
		var read int64
		read, err = rf.ReadFrom(sourceReader)
		if read > 0 {
			for _, counter := range readCounters {
				counter(read)
			}
			for _, counter := range writeCounters {
				counter(read)
			}
			gate.addRelayBytes(!direction, read)
		}
	default:
		var copied int64
		copied, err = bufio.CopyWithCounters(destinationWriter, sourceReader, source, readCounters, writeCounters, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
		gate.addRelayBytes(!direction, copied)
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
	if !gate.closed.Load() {
		gate.finish(onClose, err)
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

type connectionCopyBranch string

const (
	connectionCopyBranchWriterTo     connectionCopyBranch = "writer_to"
	connectionCopyBranchReaderFrom   connectionCopyBranch = "reader_from"
	connectionCopyBranchCopyCounters connectionCopyBranch = "copy_counters"
)

func selectConnectionCopyBranch(sourceReader io.Reader, destinationWriter io.Writer) connectionCopyBranch {
	if _, ok := sourceReader.(interface {
		io.WriterTo
		C.RouteConnectionCopyWriterTo
	}); ok {
		return connectionCopyBranchWriterTo
	}
	if _, ok := destinationWriter.(interface {
		io.ReaderFrom
		C.RouteConnectionCopyReaderFrom
	}); ok {
		return connectionCopyBranchReaderFrom
	}
	return connectionCopyBranchCopyCounters
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
		err = copyPacketUpload(ctx, source, destination)
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

// packetRelayC2SFlushInterval drains async CONNECT-UDP write queues during SOCKS→MASQUE upload relay.
const packetRelayC2SFlushInterval = 32

// packetRelayUploadDrainTimeout bounds masque upload drain when SOCKS upload relay ends (sharded H2 async workers).
const packetRelayUploadDrainTimeout = 5 * time.Second

func flushC2SWritesChain(conn any) {
	for conn != nil {
		if f, ok := conn.(interface{ FlushC2SWrites() }); ok {
			f.FlushC2SWrites()
		}
		up, ok := conn.(interface{ Upstream() any })
		if !ok {
			break
		}
		conn = up.Upstream()
	}
}

func drainUploadChain(conn any, timeout time.Duration) {
	var drainer interface {
		AwaitUploadDrain(time.Duration) error
	}
	for cur := conn; cur != nil; {
		if d, ok := cur.(interface {
			AwaitUploadDrain(time.Duration) error
		}); ok {
			drainer = d
		}
		if f, ok := cur.(interface{ FlushC2SWrites() }); ok {
			f.FlushC2SWrites()
		}
		up, ok := cur.(interface{ Upstream() any })
		if !ok {
			break
		}
		cur = up.Upstream()
	}
	if drainer != nil {
		_ = drainer.AwaitUploadDrain(timeout)
	}
}

// copyPacketUpload relays inbound UDP (e.g. SOCKS5 ASSOCIATE) to masque/outbound. Periodic C2S flush
// prevents server-side async writeCh backpressure from stalling SOCKS recv and dropping bursts.
func copyPacketUpload(ctx context.Context, source N.PacketReader, destination N.PacketWriter) error {
	buffer := buf.NewPacket()
	defer buffer.Release()
	packetsSinceFlush := 0
	defer drainUploadChain(destination, packetRelayUploadDrainTimeout)
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		default:
		}
		buffer.Reset()
		destinationAddr, err := source.ReadPacket(buffer)
		if err != nil {
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
		if buffer.Start() < packetRelayMuxHeadroom || buffer.FreeLen() < packetRelayMuxHeadroom {
			clone := buf.NewPacket()
			payloadLen := buffer.Len()
			clone.Resize(packetRelayMuxHeadroom, payloadLen)
			copy(clone.Bytes(), buffer.Bytes())
			err = destination.WritePacket(clone, destinationAddr)
			clone.Release()
			if err != nil {
				return err
			}
		} else if err = destination.WritePacket(buffer, destinationAddr); err != nil {
			return err
		}
		packetsSinceFlush++
		if packetsSinceFlush >= packetRelayC2SFlushInterval {
			flushC2SWritesChain(destination)
			packetsSinceFlush = 0
		}
	}
}

// copyPacketDownload relays masque/outbound UDP to the TUN inbound side. CONNECT-UDP ICMP
// (ErrUDPPortUnreachable) must not tear down the relay — keep draining like H3 proxiedConn.
func copyPacketDownload(ctx context.Context, source N.PacketReader, destination N.PacketWriter) error {
	buffer := buf.NewPacket()
	defer buffer.Release()
	for {
		buffer.Reset()
		destinationAddr, err := source.ReadPacket(buffer)
		if err != nil {
			if isUDPPortUnreachable(err) {
				remote := udpPortUnreachableRemote(err, destinationAddr)
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
