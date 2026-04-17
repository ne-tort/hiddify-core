package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ranges"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"go4.org/netipx"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.TunInboundOptions](registry, C.TypeTun, NewInbound)
}

type Inbound struct {
	tag            string
	ctx            context.Context
	router         adapter.Router
	networkManager adapter.NetworkManager
	logger         log.ContextLogger
	//nolint:staticcheck
	inboundOptions              option.InboundOptions
	tunOptions                  tun.Options
	udpTimeout                  time.Duration
	stack                       string
	tunIf                       tun.Tun
	tunStack                    tun.Stack
	platformInterface           adapter.PlatformInterface
	platformOptions             option.TunPlatformOptions
	autoRedirect                tun.AutoRedirect
	routeRuleSet                []adapter.RuleSet
	routeRuleSetCallback        []*list.Element[adapter.RuleSetUpdateCallback]
	routeExcludeRuleSet         []adapter.RuleSet
	routeExcludeRuleSetCallback []*list.Element[adapter.RuleSetUpdateCallback]
	routeAddressSet             []*netipx.IPSet
	routeExcludeAddressSet      []*netipx.IPSet

	l3OverlayOutboundTag string
	l3OverlayPrefixes    []netip.Prefix
	l3OverlaySocksDest   M.Socksaddr
	l3OverlayUDPDest     *net.UDPAddr
	l3OverlayCancel      context.CancelFunc
	l3OverlayPacketConn  net.PacketConn
	l3OverlayRewriteSrc  netip.Addr
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TunInboundOptions) (adapter.Inbound, error) {
	address := options.Address
	var deprecatedAddressUsed bool

	//nolint:staticcheck
	if len(options.Inet4Address) > 0 {
		address = append(address, options.Inet4Address...)
		deprecatedAddressUsed = true
	}

	//nolint:staticcheck
	if len(options.Inet6Address) > 0 {
		address = append(address, options.Inet6Address...)
		deprecatedAddressUsed = true
	}
	inet4Address := common.Filter(address, func(it netip.Prefix) bool {
		return it.Addr().Is4()
	})
	inet6Address := common.Filter(address, func(it netip.Prefix) bool {
		return it.Addr().Is6()
	})

	routeAddress := options.RouteAddress

	//nolint:staticcheck
	if len(options.Inet4RouteAddress) > 0 {
		routeAddress = append(routeAddress, options.Inet4RouteAddress...)
		deprecatedAddressUsed = true
	}

	//nolint:staticcheck
	if len(options.Inet6RouteAddress) > 0 {
		routeAddress = append(routeAddress, options.Inet6RouteAddress...)
		deprecatedAddressUsed = true
	}
	inet4RouteAddress := common.Filter(routeAddress, func(it netip.Prefix) bool {
		return it.Addr().Is4()
	})
	inet6RouteAddress := common.Filter(routeAddress, func(it netip.Prefix) bool {
		return it.Addr().Is6()
	})

	routeExcludeAddress := options.RouteExcludeAddress

	//nolint:staticcheck
	if len(options.Inet4RouteExcludeAddress) > 0 {
		routeExcludeAddress = append(routeExcludeAddress, options.Inet4RouteExcludeAddress...)
		deprecatedAddressUsed = true
	}

	//nolint:staticcheck
	if len(options.Inet6RouteExcludeAddress) > 0 {
		routeExcludeAddress = append(routeExcludeAddress, options.Inet6RouteExcludeAddress...)
		deprecatedAddressUsed = true
	}
	inet4RouteExcludeAddress := common.Filter(routeExcludeAddress, func(it netip.Prefix) bool {
		return it.Addr().Is4()
	})
	inet6RouteExcludeAddress := common.Filter(routeExcludeAddress, func(it netip.Prefix) bool {
		return it.Addr().Is6()
	})

	if deprecatedAddressUsed {
		deprecated.Report(ctx, deprecated.OptionTUNAddressX)
	}

	//nolint:staticcheck
	if options.GSO {
		deprecated.Report(ctx, deprecated.OptionTUNGSO)
	}

	platformInterface := service.FromContext[adapter.PlatformInterface](ctx)
	tunMTU := options.MTU
	enableGSO := C.IsLinux && options.Stack == "gvisor" && platformInterface == nil && tunMTU > 0 && tunMTU < 49152
	if tunMTU == 0 {
		if platformInterface != nil && platformInterface.UnderNetworkExtension() {
			// In Network Extension, when MTU exceeds 4064 (4096-UTUN_IF_HEADROOM_SIZE), the performance of tun will drop significantly, which may be a system bug.
			tunMTU = 4064
		} else if C.IsAndroid {
			// Some Android devices report ENOBUFS when using MTU 65535
			tunMTU = 9000
		} else {
			tunMTU = 65535
		}
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	var err error
	includeUID := uidToRange(options.IncludeUID)
	if len(options.IncludeUIDRange) > 0 {
		includeUID, err = parseRange(includeUID, options.IncludeUIDRange)
		if err != nil {
			return nil, E.Cause(err, "parse include_uid_range")
		}
	}
	excludeUID := uidToRange(options.ExcludeUID)
	if len(options.ExcludeUIDRange) > 0 {
		excludeUID, err = parseRange(excludeUID, options.ExcludeUIDRange)
		if err != nil {
			return nil, E.Cause(err, "parse exclude_uid_range")
		}
	}

	tableIndex := options.IPRoute2TableIndex
	if tableIndex == 0 {
		tableIndex = tun.DefaultIPRoute2TableIndex
	}
	ruleIndex := options.IPRoute2RuleIndex
	if ruleIndex == 0 {
		ruleIndex = tun.DefaultIPRoute2RuleIndex
	}
	inputMark := uint32(options.AutoRedirectInputMark)
	if inputMark == 0 {
		inputMark = tun.DefaultAutoRedirectInputMark
	}
	outputMark := uint32(options.AutoRedirectOutputMark)
	if outputMark == 0 {
		outputMark = tun.DefaultAutoRedirectOutputMark
	}
	resetMark := uint32(options.AutoRedirectResetMark)
	if resetMark == 0 {
		resetMark = tun.DefaultAutoRedirectResetMark
	}
	nfQueue := options.AutoRedirectNFQueue
	if nfQueue == 0 {
		nfQueue = tun.DefaultAutoRedirectNFQueue
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	multiPendingPackets := C.IsDarwin && ((options.Stack == "gvisor" && tunMTU < 32768) || (options.Stack != "gvisor" && options.MTU <= 9000))
	inbound := &Inbound{
		tag:            tag,
		ctx:            ctx,
		router:         router,
		networkManager: networkManager,
		logger:         logger,
		inboundOptions: options.InboundOptions,
		tunOptions: tun.Options{
			Name:                     options.InterfaceName,
			MTU:                      tunMTU,
			GSO:                      enableGSO,
			Inet4Address:             inet4Address,
			Inet6Address:             inet6Address,
			AutoRoute:                options.AutoRoute,
			IPRoute2TableIndex:       tableIndex,
			IPRoute2RuleIndex:        ruleIndex,
			AutoRedirectInputMark:    inputMark,
			AutoRedirectOutputMark:   outputMark,
			AutoRedirectResetMark:    resetMark,
			AutoRedirectNFQueue:      nfQueue,
			ExcludeMPTCP:             options.ExcludeMPTCP,
			Inet4LoopbackAddress:     common.Filter(options.LoopbackAddress, netip.Addr.Is4),
			Inet6LoopbackAddress:     common.Filter(options.LoopbackAddress, netip.Addr.Is6),
			StrictRoute:              options.StrictRoute,
			IncludeInterface:         options.IncludeInterface,
			ExcludeInterface:         options.ExcludeInterface,
			Inet4RouteAddress:        inet4RouteAddress,
			Inet6RouteAddress:        inet6RouteAddress,
			Inet4RouteExcludeAddress: inet4RouteExcludeAddress,
			Inet6RouteExcludeAddress: inet6RouteExcludeAddress,
			IncludeUID:               includeUID,
			ExcludeUID:               excludeUID,
			IncludeAndroidUser:       options.IncludeAndroidUser,
			IncludePackage:           options.IncludePackage,
			ExcludePackage:           options.ExcludePackage,
			InterfaceMonitor:         networkManager.InterfaceMonitor(),
			EXP_MultiPendingPackets:  multiPendingPackets,
		},
		udpTimeout:        udpTimeout,
		stack:             options.Stack,
		platformInterface: platformInterface,
		platformOptions:   common.PtrValueOrDefault(options.Platform),
	}
	for _, routeAddressSet := range options.RouteAddressSet {
		ruleSet, loaded := router.RuleSet(routeAddressSet)
		if !loaded {
			return nil, E.New("parse route_address_set: rule-set not found: ", routeAddressSet)
		}
		inbound.routeRuleSet = append(inbound.routeRuleSet, ruleSet)
	}
	for _, routeExcludeAddressSet := range options.RouteExcludeAddressSet {
		ruleSet, loaded := router.RuleSet(routeExcludeAddressSet)
		if !loaded {
			return nil, E.New("parse route_exclude_address_set: rule-set not found: ", routeExcludeAddressSet)
		}
		inbound.routeExcludeRuleSet = append(inbound.routeExcludeRuleSet, ruleSet)
	}
	if options.AutoRedirect {
		if !options.AutoRoute {
			return nil, E.New("`auto_route` is required by `auto_redirect`")
		}
		disableNFTables, dErr := strconv.ParseBool(os.Getenv("DISABLE_NFTABLES"))
		inbound.autoRedirect, err = tun.NewAutoRedirect(tun.AutoRedirectOptions{
			TunOptions:             &inbound.tunOptions,
			Context:                ctx,
			Handler:                (*autoRedirectHandler)(inbound),
			Logger:                 logger,
			NetworkMonitor:         networkManager.NetworkMonitor(),
			InterfaceFinder:        networkManager.InterfaceFinder(),
			TableName:              "sing-box",
			DisableNFTables:        dErr == nil && disableNFTables,
			RouteAddressSet:        &inbound.routeAddressSet,
			RouteExcludeAddressSet: &inbound.routeExcludeAddressSet,
		})
		if err != nil {
			return nil, E.Cause(err, "initialize auto-redirect")
		}
		if !C.IsAndroid {
			inbound.tunOptions.AutoRedirectMarkMode = true
			err = networkManager.RegisterAutoRedirectOutputMark(inbound.tunOptions.AutoRedirectOutputMark)
			if err != nil {
				return nil, err
			}
		}
	}
	if options.L3OverlayOutbound != "" && len(options.L3OverlayRouteAddress) == 0 {
		return nil, E.New("tun: l3_overlay_route_address is required when l3_overlay_outbound is set")
	}
	if len(options.L3OverlayRouteAddress) > 0 && options.L3OverlayOutbound == "" {
		return nil, E.New("tun: l3_overlay_outbound is required when l3_overlay_route_address is set")
	}
	if options.AutoRedirect && options.L3OverlayOutbound != "" {
		return nil, E.New("tun: auto_redirect cannot be used with l3_overlay_outbound")
	}
	if options.L3OverlayOutbound != "" {
		if options.MTU == 0 && tunMTU > 9000 {
			// Jumbo defaults are unreliable for raw IP overlay under long SMB flows.
			tunMTU = 1500
			inbound.tunOptions.MTU = tunMTU
			logger.Warn("tun: normalize MTU to 1500 for l3_overlay_outbound")
		}
		destStr := options.L3OverlayDestination
		if destStr == "" {
			destStr = "198.18.0.1:33333"
		}
		sa := M.ParseSocksaddr(destStr)
		if !sa.IsValid() {
			return nil, E.New("invalid l3_overlay_destination")
		}
		inbound.l3OverlaySocksDest = sa
		inbound.l3OverlayUDPDest = net.UDPAddrFromAddrPort(netip.AddrPortFrom(sa.Addr, sa.Port))
		inbound.l3OverlayOutboundTag = options.L3OverlayOutbound
		for _, p := range options.L3OverlayRouteAddress {
			inbound.l3OverlayPrefixes = append(inbound.l3OverlayPrefixes, p)
		}
		for _, ap := range inet4Address {
			a := ap.Addr().Unmap()
			if !a.Is4() {
				continue
			}
			for _, rp := range inbound.l3OverlayPrefixes {
				if rp.Contains(a) {
					inbound.l3OverlayRewriteSrc = a
					break
				}
			}
			if inbound.l3OverlayRewriteSrc.IsValid() {
				break
			}
		}
	}
	return inbound, nil
}

func uidToRange(uidList badoption.Listable[uint32]) []ranges.Range[uint32] {
	return common.Map(uidList, func(uid uint32) ranges.Range[uint32] {
		return ranges.NewSingle(uid)
	})
}

func parseRange(uidRanges []ranges.Range[uint32], rangeList []string) ([]ranges.Range[uint32], error) {
	for _, uidRange := range rangeList {
		if !strings.Contains(uidRange, ":") {
			return nil, E.New("missing ':' in range: ", uidRange)
		}
		subIndex := strings.Index(uidRange, ":")
		if subIndex == 0 {
			return nil, E.New("missing range start: ", uidRange)
		} else if subIndex == len(uidRange)-1 {
			return nil, E.New("missing range end: ", uidRange)
		}
		var start, end uint64
		var err error
		start, err = strconv.ParseUint(uidRange[:subIndex], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range start")
		}
		end, err = strconv.ParseUint(uidRange[subIndex+1:], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range end")
		}
		uidRanges = append(uidRanges, ranges.New(uint32(start), uint32(end)))
	}
	return uidRanges, nil
}

func (t *Inbound) Type() string {
	return C.TypeTun
}

func (t *Inbound) Tag() string {
	return t.tag
}

func (t *Inbound) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateStart:
		if C.IsAndroid && t.platformInterface == nil {
			t.tunOptions.BuildAndroidRules(t.networkManager.PackageManager())
		}
		if t.tunOptions.Name == "" {
			t.tunOptions.Name = tun.CalculateInterfaceName("")
		}
		if t.platformInterface == nil {
			t.routeAddressSet = common.FlatMap(t.routeRuleSet, adapter.RuleSet.ExtractIPSet)
			for _, routeRuleSet := range t.routeRuleSet {
				ipSets := routeRuleSet.ExtractIPSet()
				if len(ipSets) == 0 {
					t.logger.Warn("route_address_set: no destination IP CIDR rules found in rule-set: ", routeRuleSet.Name())
				}
				routeRuleSet.IncRef()
				t.routeAddressSet = append(t.routeAddressSet, ipSets...)
				if t.autoRedirect != nil {
					t.routeRuleSetCallback = append(t.routeRuleSetCallback, routeRuleSet.RegisterCallback(t.updateRouteAddressSet))
				}
			}
			t.routeExcludeAddressSet = common.FlatMap(t.routeExcludeRuleSet, adapter.RuleSet.ExtractIPSet)
			for _, routeExcludeRuleSet := range t.routeExcludeRuleSet {
				ipSets := routeExcludeRuleSet.ExtractIPSet()
				if len(ipSets) == 0 {
					t.logger.Warn("route_address_set: no destination IP CIDR rules found in rule-set: ", routeExcludeRuleSet.Name())
				}
				routeExcludeRuleSet.IncRef()
				t.routeExcludeAddressSet = append(t.routeExcludeAddressSet, ipSets...)
				if t.autoRedirect != nil {
					t.routeExcludeRuleSetCallback = append(t.routeExcludeRuleSetCallback, routeExcludeRuleSet.RegisterCallback(t.updateRouteAddressSet))
				}
			}
		}
		var (
			tunInterface tun.Tun
			err          error
		)
		monitor := taskmonitor.New(t.logger, C.StartTimeout)
		tunOptions := t.tunOptions
		if t.autoRedirect == nil && !(runtime.GOOS == "android" && t.platformInterface != nil) {
			for _, ipSet := range t.routeAddressSet {
				for _, prefix := range ipSet.Prefixes() {
					if prefix.Addr().Is4() {
						tunOptions.Inet4RouteAddress = append(tunOptions.Inet4RouteAddress, prefix)
					} else {
						tunOptions.Inet6RouteAddress = append(tunOptions.Inet6RouteAddress, prefix)
					}
				}
			}
			for _, ipSet := range t.routeExcludeAddressSet {
				for _, prefix := range ipSet.Prefixes() {
					if prefix.Addr().Is4() {
						tunOptions.Inet4RouteExcludeAddress = append(tunOptions.Inet4RouteExcludeAddress, prefix)
					} else {
						tunOptions.Inet6RouteExcludeAddress = append(tunOptions.Inet6RouteExcludeAddress, prefix)
					}
				}
			}
		}
		monitor.Start("open interface")
		if t.platformInterface != nil && t.platformInterface.UsePlatformInterface() {
			tunInterface, err = t.platformInterface.OpenInterface(&tunOptions, t.platformOptions)
		} else {
			if HookBeforeCreatePlatformInterface != nil {
				HookBeforeCreatePlatformInterface()
			}
			tunInterface, err = tun.New(tunOptions)
		}
		monitor.Finish()
		t.tunOptions.Name = tunOptions.Name
		if err != nil {
			return E.Cause(err, "configure tun interface")
		}
		t.logger.Trace("creating stack")
		t.tunIf = tunInterface
		var (
			forwarderBindInterface bool
			includeAllNetworks     bool
		)
		if t.platformInterface != nil {
			forwarderBindInterface = true
			includeAllNetworks = t.platformInterface.NetworkExtensionIncludeAllNetworks()
		}
		var (
			l3Prefixes []netip.Prefix
			l3Send     func([]byte) error
			l3SendErr  func(error)
		)
		if t.l3OverlayOutboundTag != "" && len(t.l3OverlayPrefixes) > 0 {
			outManager := service.FromContext[adapter.OutboundManager](t.ctx)
			ob, ok := outManager.Outbound(t.l3OverlayOutboundTag)
			if !ok {
				return E.New("tun: l3_overlay_outbound not found: ", t.l3OverlayOutboundTag)
			}
			pctx, cancel := context.WithCancel(t.ctx)
			t.l3OverlayCancel = cancel
			pConn, err := ob.ListenPacket(pctx, t.l3OverlaySocksDest)
			if err != nil {
				cancel()
				return E.Cause(err, "l3 overlay ListenPacket")
			}
			t.l3OverlayPacketConn = pConn
			udpAddr := t.l3OverlayUDPDest
			if primeErr := primeL3OverlayHandshake(t.logger, pConn, udpAddr); primeErr != nil {
				t.logger.Warn("l3 overlay prime handshake (non-fatal): ", primeErr)
			}
			l3Prefixes = t.l3OverlayPrefixes
			rewriteSrc := t.l3OverlayRewriteSrc
			var overlayConn atomic.Value // stores net.PacketConn
			overlayConn.Store(pConn)
			var reconnectMu sync.Mutex
			var overlaySendErrors atomic.Uint64
			var lastOverlaySendLog atomic.Int64
			l3Send = func(packet []byte) error {
				if rewriteSrc.IsValid() {
					b := append([]byte(nil), packet...)
					rewriteL3OverlayEgressIPv4(b, rewriteSrc)
					packet = b
				}
				connAny := overlayConn.Load()
				conn, _ := connAny.(net.PacketConn)
				if conn == nil {
					return net.ErrClosed
				}
				_, err := conn.WriteTo(packet, udpAddr)
				if err == nil {
					return nil
				}
				if !isOverlayWriteRecoverable(err) {
					return err
				}
				reconnectMu.Lock()
				defer reconnectMu.Unlock()
				latestAny := overlayConn.Load()
				latestConn, _ := latestAny.(net.PacketConn)
				if latestConn != nil && latestConn != conn {
					if _, retryErr := latestConn.WriteTo(packet, udpAddr); retryErr == nil {
						return nil
					}
				}
				newConn, connErr := ob.ListenPacket(pctx, t.l3OverlaySocksDest)
				if connErr != nil {
					return err
				}
				if latestConn != nil {
					_ = latestConn.Close()
				}
				overlayConn.Store(newConn)
				t.l3OverlayPacketConn = newConn
				if primeErr := primeL3OverlayHandshake(t.logger, newConn, udpAddr); primeErr != nil {
					t.logger.Warn("l3 overlay prime after reconnect (non-fatal): ", primeErr)
				}
				go t.l3OverlayReceiveLoop(newConn)
				_, retryErr := newConn.WriteTo(packet, udpAddr)
				if retryErr == nil {
					return nil
				}
				return retryErr
			}
			l3SendErr = func(err error) {
				count := overlaySendErrors.Add(1)
				now := time.Now().UnixNano()
				lastLoggedAt := lastOverlaySendLog.Load()
				if now-lastLoggedAt >= int64(5*time.Second) && lastOverlaySendLog.CompareAndSwap(lastLoggedAt, now) {
					t.logger.Warn("l3 overlay send error: ", err, " total_failures=", count)
				}
			}
			go t.l3OverlayReceiveLoop(pConn)
		}
		tunStack, err := tun.NewStack(t.stack, tun.StackOptions{
			Context:                t.ctx,
			Tun:                    tunInterface,
			TunOptions:             t.tunOptions,
			UDPTimeout:             t.udpTimeout,
			Handler:                t,
			Logger:                 t.logger,
			ForwarderBindInterface: forwarderBindInterface,
			InterfaceFinder:        t.networkManager.InterfaceFinder(),
			IncludeAllNetworks:     includeAllNetworks,
			L3OverlayRoutePrefixes: l3Prefixes,
			L3OverlaySend:          l3Send,
			L3OverlaySendError:     l3SendErr,
		})
		if err != nil {
			return err
		}
		t.tunStack = tunStack
		t.logger.Info("started at ", t.tunOptions.Name)
	case adapter.StartStatePostStart:
		monitor := taskmonitor.New(t.logger, C.StartTimeout)
		monitor.Start("starting tun stack")
		err := t.tunStack.Start()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "starting tun stack")
		}
		monitor.Start("starting tun interface")
		err = t.tunIf.Start()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "starting TUN interface")
		}
		if t.autoRedirect != nil {
			monitor.Start("initialize auto-redirect")
			err := t.autoRedirect.Start()
			monitor.Finish()
			if err != nil {
				return E.Cause(err, "auto-redirect")
			}
		}
		t.routeAddressSet = nil
		t.routeExcludeAddressSet = nil
	}
	return nil
}

func isOverlayWriteRecoverable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection reset") || strings.Contains(msg, "use of closed network connection")
}

func (t *Inbound) updateRouteAddressSet(it adapter.RuleSet) {
	t.routeAddressSet = common.FlatMap(t.routeRuleSet, adapter.RuleSet.ExtractIPSet)
	t.routeExcludeAddressSet = common.FlatMap(t.routeExcludeRuleSet, adapter.RuleSet.ExtractIPSet)
	t.autoRedirect.UpdateRouteAddressSet()
	t.routeAddressSet = nil
	t.routeExcludeAddressSet = nil
}

func (t *Inbound) Close() error {
	if t.l3OverlayCancel != nil {
		t.l3OverlayCancel()
	}
	if t.l3OverlayPacketConn != nil {
		t.l3OverlayPacketConn.Close()
	}
	return common.Close(
		t.tunStack,
		t.tunIf,
		t.autoRedirect,
	)
}

func (t *Inbound) l3OverlayReceiveLoop(conn net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if E.IsClosed(err) || errors.Is(err, net.ErrClosed) {
				return
			}
			t.logger.Trace("l3 overlay read: ", err)
			return
		}
		if n == 0 {
			continue
		}
		_, werr := t.tunIf.Write(buf[:n])
		if werr != nil {
			t.logger.Trace("l3 overlay tun write: ", werr)
		}
	}
}

func (t *Inbound) PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	var ipVersion uint8
	if !destination.IsIPv6() {
		ipVersion = 4
	} else {
		ipVersion = 6
	}
	routeDestination, err := t.router.PreMatch(adapter.InboundContext{
		Inbound:        t.tag,
		InboundType:    C.TypeTun,
		IPVersion:      ipVersion,
		Network:        network,
		Source:         source,
		Destination:    destination,
		InboundOptions: t.inboundOptions,
	}, routeContext, timeout, false)
	if err != nil {
		switch {
		case rule.IsBypassed(err):
			err = nil
		case rule.IsRejected(err):
			t.logger.Trace("reject ", network, " connection from ", source.AddrString(), " to ", destination.AddrString())
		default:
			if network == N.NetworkICMP {
				t.logger.Warn(E.Cause(err, "link ", network, " connection from ", source.AddrString(), " to ", destination.AddrString()))
			}
		}
	}
	return routeDestination, err
}

func (t *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = t.tag
	metadata.InboundType = C.TypeTun
	metadata.Source = source
	metadata.Destination = destination
	//nolint:staticcheck
	metadata.InboundOptions = t.inboundOptions
	t.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
	t.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	t.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (t *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = t.tag
	metadata.InboundType = C.TypeTun
	metadata.Source = source
	metadata.Destination = destination
	//nolint:staticcheck
	metadata.InboundOptions = t.inboundOptions
	t.logger.InfoContext(ctx, "inbound packet connection from ", metadata.Source)
	t.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
	t.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

type autoRedirectHandler Inbound

func (t *autoRedirectHandler) PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	var ipVersion uint8
	if !destination.IsIPv6() {
		ipVersion = 4
	} else {
		ipVersion = 6
	}
	routeDestination, err := t.router.PreMatch(adapter.InboundContext{
		Inbound:        t.tag,
		InboundType:    C.TypeTun,
		IPVersion:      ipVersion,
		Network:        network,
		Source:         source,
		Destination:    destination,
		InboundOptions: t.inboundOptions,
	}, routeContext, timeout, true)
	if err != nil {
		switch {
		case rule.IsBypassed(err):
			t.logger.Trace("bypass ", network, " connection from ", source.AddrString(), " to ", destination.AddrString())
		case rule.IsRejected(err):
			t.logger.Trace("reject ", network, " connection from ", source.AddrString(), " to ", destination.AddrString())
		default:
			if network == N.NetworkICMP {
				t.logger.Warn(E.Cause(err, "link ", network, " connection from ", source.AddrString(), " to ", destination.AddrString()))
			}
		}
	}
	return routeDestination, err
}

func (t *autoRedirectHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = t.tag
	metadata.InboundType = C.TypeTun
	metadata.Source = source
	metadata.Destination = destination
	//nolint:staticcheck
	metadata.InboundOptions = t.inboundOptions
	t.logger.InfoContext(ctx, "inbound redirect connection from ", metadata.Source)
	t.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	t.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (t *autoRedirectHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	panic("unexcepted")
}
