package session

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
	"github.com/yosida95/uritemplate/v3"
)

// BootstrapCoreSession fills CoreSession fields shared by the masque coreSession wrapper.
// udpLayer is the normalized overlay layer ("h2"|"h3") for UDPHTTPLayer.
func BootstrapCoreSession(options ClientOptions, templateUDP, templateIP, templateTCP *uritemplate.Template) (CoreSession, string) {
	dm := strings.ToLower(strings.TrimSpace(options.DataplaneMode))
	if dm == "" {
		dm = option.MasqueDataplaneDefault
	}
	tcpCapable := true
	effectiveCeiling := int(options.ConnectIPDatagramCeiling)
	if effectiveCeiling <= 0 {
		effectiveCeiling = mcip.DefaultDatagramCeilingMax
	}
	if effectiveCeiling < 1280 {
		effectiveCeiling = 1280
	}
	ceilingMax := mcip.MaxConfiguredDatagramCeiling
	if effectiveCeiling > ceilingMax {
		effectiveCeiling = ceilingMax
	}
	selfHosted := mcip.SelfHosted(len(options.WarpMasqueClientCert.Certificate) > 0)
	udpPayloadHardCap := mcip.UDPWriteHardCapFor(selfHosted)
	initialPayload := effectiveCeiling - 28
	if initialPayload < 512 {
		initialPayload = 512
	}
	if initialPayload > udpPayloadHardCap {
		initialPayload = udpPayloadHardCap
	}
	masqueUDPWriteMax := h3t.UDPWriteMax(effectiveCeiling, udpPayloadHardCap)
	udpLayer := strings.ToLower(strings.TrimSpace(options.MasqueEffectiveHTTPLayer))
	if udpLayer != option.MasqueHTTPLayerH2 {
		udpLayer = option.MasqueHTTPLayerH3
	}
	quicStyleDatagrams := udpLayer != option.MasqueHTTPLayerH2
	cs := CoreSession{
		Options:                    options,
		TemplateUDP:                templateUDP,
		TemplateIP:                 templateIP,
		TemplateTCP:                templateTCP,
		Caps: CapabilitySet{
			ExtendedConnect: true,
			Datagrams:       quicStyleDatagrams,
			CapsuleProtocol: true,
			ConnectUDP:      true,
			ConnectIP:       true,
			ConnectTCP:      tcpCapable,
		},
		HopOrder:                   ResolveHopOrder(options.Hops),
		ConnectIPDatagramCeiling:   effectiveCeiling,
		ConnectIPUDPPayloadHardCap: udpPayloadHardCap,
		ConnectIPTCPDatagramSlack:  mcip.TCPHTTP3DatagramSlack,
		MasqueUDPWriteMax:          masqueUDPWriteMax,
		ConnectIPPMTUState:         NewConnectIPPMTUState(initialPayload, 512, initialPayload),
		HTTPLayerAuto:              options.HTTPLayerAuto,
	}
	return cs, udpLayer
}
