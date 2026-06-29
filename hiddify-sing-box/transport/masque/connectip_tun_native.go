package masque

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
	ciptun "github.com/sagernet/sing-box/transport/masque/connectip/tun"
	"github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
)

// ConnectIPTunNativeL3 configures sing-tun gVisor L3 overlay for native connect_ip (W-IP-ARCH-2).
// Egress: tun read → L3OverlaySend (IP steal) → WritePacket. Ingress: wire → DNAT → TunIngressWrite (host) OR stackInject (synth).
// Call startIngress after tunStack.Start(); stop tears down plane + native L3 mode.
func ConnectIPTunNativeL3(
	ctx context.Context,
	tunIf tun.Tun,
	sess ClientSession,
	routePrefixes []netip.Prefix,
	tunHost netip.Addr,
	wireLocal netip.Addr,
) (l3Prefixes []netip.Prefix, l3Send func([]byte) error, l3SendErr func(error), startIngress func(context.Context) error, bindStackIngress func(func([]byte) error), stop func(), err error) {
	if sess == nil {
		return nil, nil, nil, nil, nil, nil, nil
	}
	ipSess, err := sess.OpenIPSession(ctx)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	leaveL3 := enterConnectIPNativeL3Mode(sess)
	writer, reader, err := connectIPNativeL3PlaneEndpoints(ipSess)
	if err != nil {
		if leaveL3 != nil {
			leaveL3()
		}
		return nil, nil, nil, nil, nil, nil, err
	}
	if !wireLocal.IsValid() {
		wireLocal = netip.MustParseAddr("198.18.0.1")
	}
	if !tunHost.IsValid() {
		tunHost = wireLocal
	}
	nat := ciptun.OverlayNAT{TunHost: tunHost, WireLocal: wireLocal}
	if len(routePrefixes) > 0 {
		virt := routePrefixes[0].Addr()
		if virt.IsValid() && virt == netip.MustParseAddr("198.18.0.99") {
			nat.VirtTarget = virt
			nat.WireTarget = netip.MustParseAddr("127.0.0.1")
		}
	}
	hostKernel := tunIf != nil
	var hostTunWrite func([]byte) (int, error)
	if hostKernel {
		hostTunWrite = ciptun.TunIngressWrite(tunIf)
	}
	bridge := ciptun.NewL3OverlayBridge(
		hostTunWrite,
		writer,
		readPacketCtxAdapter{read: reader.ReadPacketWithContext},
		nat,
	)
	if hostKernel {
		if hr, ok := tunIf.(interface {
			ReadHostEgress(context.Context, []byte) (int, error)
		}); ok {
			rawRead := ciptun.HostEgressReader(hr.ReadHostEgress)
			const vnetHdr = false
			const useReadAhead = true
			hostRead := rawRead
			var readAheadBatch ciptun.HostEgressBatchReader
			if useReadAhead {
				hostRead, readAheadBatch = ciptun.WrapHostEgressReadAheadBatch(ctx, rawRead)
			}
			bridge.SetHostEgressRead(hostRead, routePrefixes)
			var innerBatch ciptun.HostEgressBatchReader
			nativeVNetBatch := false
			if vnetHdr {
				if br, ok := tunIf.(interface {
					ReadHostEgressBatch(context.Context, [][]byte, int) (int, error)
				}); ok {
					innerBatch = ciptun.AdaptNativeHostEgressBatch(br.ReadHostEgressBatch)
					nativeVNetBatch = true
				}
			}
			if innerBatch == nil {
				if readAheadBatch != nil {
					innerBatch = readAheadBatch
				} else {
					innerBatch = ciptun.HostEgressReaderAsBatch(hostRead)
				}
			}
			batch := innerBatch
			// VNetHdr native batch: second-layer read-ahead on syscall-coalesced reads.
			useBatchReadAhead := nativeVNetBatch && useReadAhead
			if useBatchReadAhead {
				batch = ciptun.WrapHostEgressBatchReadAhead(ctx, innerBatch)
			}
			bridge.SetHostEgressBatch(batch)
			log.Printf("connect-ip native l3: host egress wired type=%T vnet_native_batch=%v read_ahead=%v batch_read_ahead=%v",
				tunIf, nativeVNetBatch, useReadAhead, useBatchReadAhead)
		} else {
			log.Printf("connect-ip native l3: host egress NOT wired type=%T", tunIf)
		}
	}
	egressSess := &l3BridgeEgressSession{IPPacketSession: ipSess, bridge: bridge}
	var nativeNS *cip.Netstack
	if !hostKernel {
		var errNS error
		nativeNS, errNS = cip.NewNetstackForSession(ctx, egressSess, cip.NetstackOptions{
			LocalIPv4: tunHost,
			LocalIPv6: netip.MustParseAddr("fd00::1"),
			MTU:       cip.H3NetstackMTU(cip.DefaultDatagramCeilingMax),
		})
		if errNS != nil {
			if leaveL3 != nil {
				leaveL3()
			}
			return nil, nil, nil, nil, nil, nil, errNS
		}
		bridge.SetStackIngressInject(func(p []byte) error {
			nativeNS.InjectInboundClone(p)
			return nil
		})
	}
	plane := ciptun.NewNativeL3PlaneSession(bridge)
	if cs, ok := sess.(*coreSession); ok {
		cs.connectIPNativeL3Plane.Store(plane)
		cs.connectIPNativeL3Netstack.Store(nativeNS)
		cs.connectIPNativeL3EgressSess.Store(egressSess)
		plane.SetReadFatalHook(cs.noteConnectIPNativeL3IngressFatal)
		flushEgress := func() {
			reader := cs.ipIngressPacketReader.Load()
			if reader == nil {
				return
			}
			reader.FlushEgressBatch()
		}
		if hostKernel {
			bridge.SetPumpWakeHooks(cippump.WakeHooks{}, flushEgress)
		} else {
			bridge.SetIngressWakeNote(cs.noteConnectIPNativeL3IngressWake)
			bridge.SetPumpWakeHooks(cippump.WakeHooks{
				TakeIngressWakePending: cs.ConnectIPIngressAckWake.TakePending,
				PokeEgressTransport:    flushEgress,
			}, flushEgress)
		}
	}
	if hook, ok := sess.(interface {
		AfterNativeL3ShortTCP(context.Context, netip.AddrPort, uint64)
	}); ok {
		bridge.SetShortFlowHook(func(dst netip.AddrPort, egressBytes uint64) {
			hook.AfterNativeL3ShortTCP(ctx, dst, egressBytes)
		})
	}
	bindStackIngress = func(inject func([]byte) error) {
		if hostKernel || inject == nil {
			return
		}
		bridge.SetHostIngressWrite(func(p []byte) (int, error) {
			if err := inject(p); err != nil {
				return 0, err
			}
			return len(p), nil
		})
	}
	startIngress = func(runCtx context.Context) error {
		if runCtx == nil {
			runCtx = ctx
		}
		plane.StartIngress(runCtx)
		waitCtx, cancel := context.WithTimeout(runCtx, 15*time.Second)
		defer cancel()
		if err := plane.WaitReady(waitCtx); err != nil {
			return err
		}
		if cs, ok := sess.(*coreSession); ok {
			if err := cs.WaitConnectIPNativeL3PlaneReady(waitCtx); err != nil {
				return err
			}
		}
		log.Printf("masque connect_ip native l3: datapath ready")
		return nil
	}
	stop = func() {
		if cs, ok := sess.(*coreSession); ok {
			cs.stopConnectIPNativeL3Dataplane()
		} else {
			plane.StopIngress()
			_ = bridge.Close()
		}
		if leaveL3 != nil {
			leaveL3()
		}
	}
	return routePrefixes, bridge.Send, func(err error) {
		if err != nil {
			log.Printf("masque connect_ip tun l3 overlay send error: %v", err)
		}
	}, startIngress, bindStackIngress, stop, nil
}

// DialNativeL3TCP dials over the connectip netstack wired by ConnectIPTunNativeL3.
func DialNativeL3TCP(ctx context.Context, sess ClientSession, dest M.Socksaddr) (net.Conn, error) {
	cs, ok := sess.(*coreSession)
	if !ok {
		return nil, errors.New("connect-ip native L3 dial: not a core session")
	}
	ns := cs.connectIPNativeL3Netstack.Load()
	if ns == nil {
		return nil, errors.New("connect-ip native L3 netstack not ready")
	}
	return ns.DialContext(ctx, dest)
}

// ConnectIPTunNativeL3Eligible reports whether transport options use native connect_ip (not hybrid).
func ConnectIPTunNativeL3Eligible(transportMode, tcpTransport string) bool {
	if !strings.EqualFold(strings.TrimSpace(transportMode), "connect_ip") {
		return false
	}
	tt := strings.TrimSpace(tcpTransport)
	if tt != "" && !strings.EqualFold(tt, "connect_ip") {
		return false
	}
	return true
}

type nativeL3PacketReader interface {
	ReadPacketWithContext(context.Context, []byte) (int, error)
}

type nativeL3PacketWriter interface {
	WritePacket([]byte) ([]byte, error)
}

func connectIPNativeL3PlaneEndpoints(ipSess IPPacketSession) (nativeL3PacketWriter, nativeL3PacketReader, error) {
	reader, ok := ipSess.(nativeL3PacketReader)
	if !ok {
		return nil, nil, errors.New("connect-ip session missing ReadPacketWithContext")
	}
	writer, ok := ipSess.(nativeL3PacketWriter)
	if !ok {
		return nil, nil, errors.New("connect-ip session missing WritePacket")
	}
	return writer, reader, nil
}

type readPacketCtxAdapter struct {
	read func(context.Context, []byte) (int, error)
}

func hasReadHostEgressBatch(tunIf tun.Tun) bool {
	_, ok := tunIf.(interface {
		ReadHostEgressBatch(context.Context, [][]byte, int) (int, error)
	})
	return ok
}

func (a readPacketCtxAdapter) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	return a.read(ctx, buf)
}
