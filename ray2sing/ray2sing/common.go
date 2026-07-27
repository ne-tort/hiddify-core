package ray2sing

//based on https://github.com/XTLS/Xray-core/issues/91
//todo merge with https://github.com/XTLS/libXray/
import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

const USER_AGENT string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

type ParserFunc func(string) (*option.Outbound, error)
type EndpointParserFunc func(string) (*T.Endpoint, error)

func getTLSOptions(decoded map[string]string) T.OutboundTLSOptionsContainer {
	if !(decoded["tls"] == "tls" || decoded["security"] == "tls" || decoded["security"] == "reality") {
		return T.OutboundTLSOptionsContainer{TLS: nil}
	}

	serverName := decoded["sni"]
	if serverName == "" {
		serverName = decoded["add"]
	}

	var ECHOpts *option.OutboundECHOptions
	valECH, hasECH := decoded["ech"]
	if hasECH {
		ECHOpts = &option.OutboundECHOptions{
			Enabled: true,
		}
		if len(valECH) > 5 {
			if !strings.Contains(valECH, "-----BEGIN ECH CONFIGS-----") {
				valECH = "-----BEGIN ECH CONFIGS-----\n" + valECH + "\n-----END ECH CONFIGS-----"
			}
			ECHOpts.Config = badoption.Listable[string]{valECH}
		}
	}

	fp := decoded["fp"]
	if fp == "" && decoded["security"] == "reality" {
		fp = "chrome"
	}
	insecure, err := getOneOf(decoded, "insecure", "allowinsecure")
	if err != nil {
		insecure = "false"
	}
	tlsOptions := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   insecure == "true" || insecure == "1",
		DisableSNI: getOneOfN(decoded, "", "nosni") != "",
		ECH:        ECHOpts,
		// TLSTricks:  getTricksOptions(decoded),
	}
	if fp != "" && !tlsOptions.DisableSNI {
		tlsOptions.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: fp,
		}
	}

	if alpn, ok := decoded["alpn"]; ok && alpn != "" {
		net := getOneOfN(decoded, "net")
		if net == "" {
			net = getOneOfN(decoded, "type")
		}
		if net == "httpupgrade" || net == "ws" || net == "grpc" || net == "h2" {
			tlsOptions.ALPN = []string{"h2", "http/1.1"}
		} else {
			tlsOptions.ALPN = strings.Split(alpn, ",")
			if getALPNversion(tlsOptions.ALPN) == 3 && getOneOfN(decoded, "", "type") == "xhttp" || getOneOfN(decoded, "", "net") == "xhttp" {
				tlsOptions.UTLS = nil //TODO utls quic has bug
			}
		}

	}
	return T.OutboundTLSOptionsContainer{
		TLS: tlsOptions,
	}

}

func getTricksOptions(decoded map[string]string) any {
	// LX-STUB: option.TLSTricksOptions absent in sing-box-lx.
	_ = decoded
	return nil
}
func getFragmentOptions(decoded map[string]string) any {
	// LX-STUB: option.TLSFragmentOptions (Hiddify dialer field) absent in sing-box-lx.
	_ = decoded
	return nil
}
func getMuxOptions(decoded map[string]string) *option.OutboundMultiplexOptions {
	mux := option.OutboundMultiplexOptions{}
	mux.Protocol = decoded["muxtype"]
	if mux.Protocol == "" {
		return nil
	}
	mux.Enabled = true
	mux.MaxConnections = toInt(decoded["muxmaxc"])
	// mux.MinStreams = toInt(decoded["muxsmin"])
	mux.MaxStreams = toInt(decoded["muxsmax"])
	mux.MinStreams = toInt(decoded["mux"])
	mux.Padding = decoded["muxpad"] == "true"

	if decoded["muxup"] != "" && decoded["muxdown"] != "" {
		mux.Brutal = &option.BrutalOptions{
			Enabled:  true,
			UpMbps:   toInt(decoded["muxup"]),
			DownMbps: toInt(decoded["muxdown"]),
		}
	}
	return &mux
}
func getTransportOptions(decoded map[string]string) (*option.V2RayTransportOptions, error) {
	var transportOptions option.V2RayTransportOptions
	host, net, path := decoded["host"], decoded["net"], decoded["path"]
	if net == "" {
		net = decoded["type"]
	}
	if path == "" {
		path = decoded["servicename"]
	}
	if net == "raw" || net == "" {
		net = "tcp"
	}
	// fmoption.Printf("\n\nheaderType:%s, net:%s, type:%s\n\n", decoded["headerType"], net, decoded["type"])
	if (decoded["type"] == "http" || decoded["headertype"] == "http") && net == "tcp" {
		net = "http"
	}

	switch net {
	case "tcp":
		return nil, nil
	case "http":
		transportOptions.Type = C.V2RayTransportTypeHTTP
		if decoded["security"] != "tls" {
			transportOptions.HTTPOptions.Method = "GET"
		}
		if host != "" {
			transportOptions.HTTPOptions.Host = badoption.Listable[string]{host}
		}
		httpPath := path
		if httpPath == "" {
			httpPath = "/"
		}
		transportOptions.HTTPOptions.Path = httpPath
	case "httpupgrade":
		decoded["alpn"] = "http/1.1"
		transportOptions.Type = C.V2RayTransportTypeHTTPUpgrade
		if host != "" {
			transportOptions.HTTPUpgradeOptions.Headers = badoption.HTTPHeader{"Host": {host}}
		}
		if path != "" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			pathURL, err := url.Parse(path)
			if err != nil {
				return &option.V2RayTransportOptions{}, err
			}
			// pathQuery := pathURL.Query()
			// transportOptions.HTTPUpgradeOptions.MaxEarlyData = 0
			// transportOptions.HTTPUpgradeOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			// maxEarlyDataString := pathQuery.Get("ed")
			// if maxEarlyDataString != "" {
			// 	maxEarlyDate, err := strconv.ParseUint(maxEarlyDataString, 10, 32)
			// 	if err == nil {
			// 		// transportOptions.HTTPUpgradeOptions.MaxEarlyData = uint32(maxEarlyDate)
			// 		pathQuery.Del("ed")
			// 		pathURL.RawQuery = pathQuery.Encode()
			// 	}
			// }
			transportOptions.HTTPUpgradeOptions.Path = pathURL.String()
		}
	case "ws":
		decoded["alpn"] = "http/1.1"

		transportOptions.Type = C.V2RayTransportTypeWebsocket
		if host != "" {
			transportOptions.WebsocketOptions.Headers = badoption.HTTPHeader{"Host": {host}}
		}
		if path != "" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			pathURL, err := url.Parse(path)
			if err != nil {
				return &option.V2RayTransportOptions{}, err
			}
			pathQuery := pathURL.Query()
			transportOptions.WebsocketOptions.MaxEarlyData = 0
			transportOptions.WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			maxEarlyDataString := pathQuery.Get("ed")
			if maxEarlyDataString != "" {
				maxEarlyDate, err := strconv.ParseUint(maxEarlyDataString, 10, 32)
				if err == nil {
					transportOptions.WebsocketOptions.MaxEarlyData = uint32(maxEarlyDate)
					pathQuery.Del("ed")
					pathURL.RawQuery = pathQuery.Encode()
				}
			}
			transportOptions.WebsocketOptions.Path = pathURL.String()
		}
	case "grpc":
		decoded["alpn"] = "h2"
		transportOptions.Type = C.V2RayTransportTypeGRPC
		transportOptions.GRPCOptions = option.V2RayGRPCOptions{
			ServiceName:         path,
			IdleTimeout:         badoption.Duration(15 * time.Second),
			PingTimeout:         badoption.Duration(15 * time.Second),
			PermitWithoutStream: false,
		}
	case "quic":
		decoded["alpn"] = "h3"
		transportOptions.Type = C.V2RayTransportTypeQUIC

	case "xhttp":
		// LX-STUB: lx V2RayXHTTPOptions is flat (Host/Path/Mode…); Hiddify BaseOptions +
		// Download/extra Reality TLS are ignored at this preliminary engine-swap stage.
		transportOptions.Type = C.V2RayTransportTypeXHTTP
		xhHost, xhPath := host, path
		if extra, ok := decoded["extra"]; ok {
			x := XHTTPExtra{}
			if err := json.Unmarshal([]byte(extra), &x); err != nil {
				return nil, err
			}
			if x.Host != "" {
				xhHost = x.Host
			}
			if x.Path != "" {
				xhPath = x.Path
			}
			_ = x.DownloadSettings // LX-STUB: no Download on lx V2RayXHTTPOptions
		}
		transportOptions.XHTTPOptions = option.V2RayXHTTPOptions{
			Mode: getOneOfN(decoded, "auto", "mode"),
			Host: xhHost,
			Path: xhPath,
		}

	default:
		return nil, E.New("unknown transport type: " + net)
	}

	return &transportOptions, nil
}
func getALPNversion(s []string) int {
	if len(s) == 0 {
		return 1
	}
	if s[0] == "h3" {
		return 3
	}
	if s[0] == "h2" {
		return 2
	}
	return 1
}

// func getV2RayXHTTPBaseOptions(extraConfig map[string]any) option.V2RayXHTTPBaseOptions {
// 	opts := option.V2RayXHTTPBaseOptions{}
// 	if headers, ok := extraConfig["headers"]; ok {
// 		if headersMap, ok := headers.(map[string]string); ok {
// 			opts.Headers = headersMap
// 		}
// 	}

// 	if noGRPCHeader, ok := extraConfig["noGRPCHeader"]; ok {
// 		if noGRPCHeaderb, ok := noGRPCHeader.(bool); ok {
// 			opts.NoGRPCHeader = noGRPCHeaderb
// 		}
// 	}
// 	if noSSEHeader, ok := extraConfig["noSSEHeader"]; ok {
// 		if noSSEHeaderb, ok := noSSEHeader.(bool); ok {
// 			opts.NoGRPCHeader = noSSEHeaderb
// 		}
// 	}

//		if scMaxBufferedPosts, ok := extraConfig["scMaxBufferedPosts"]; ok {
//			if scMaxBufferedPosti, ok := scMaxBufferedPosts.(int); ok {
//				opts.ScMaxBufferedPosts = int64(scMaxBufferedPosti)
//			}
//		}
//	}
func getDialerOptions(decoded map[string]string) option.DialerOptions {
	// fragment := getFragmentOptions(decoded)
	opts := T.DialerOptions{
		// TCPFastOpen: !fragment.Enabled,
		// TLSFragment: fragment,
	}
	// Tag-style detour from share-link query (?detour=relay). URL-style chains use &&detour=.
	if d := strings.TrimSpace(decoded["detour"]); d != "" && !strings.Contains(d, "://") {
		opts.Detour = d
	}
	return opts
}

func decodeBase64IfNeeded(b64string string) (string, error) {

	decodedBytes, err := decodeBase64FaultTolerant(b64string)

	if err != nil {
		return b64string, err
	}

	return string(decodedBytes), nil
}

func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func toBool(s string, def bool) bool {
	switch strings.ToLower(s) {
	case "true":
		return true
	case "1":
		return true
	case "yes":
		return true
	case "on":
		return true
	case "false":
		return false
	case "0":
		return false
	case "no":
		return false
	case "off":
		return false
	default:
		return def
	}
}
func toIntN(s string) *int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &i
}

func toFloatN(s string) *float64 {
	i, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &i
}
func toUInt16(s string, defaultPort uint16) uint16 {
	val, err := strconv.ParseInt(s, 10, 17)
	if err != nil {
		// fmoption.Printf("err %v", err)
		// handle the error appropriately; here we return 0
		return defaultPort
	}
	return uint16(val)
}

func toInt16(s string, defaultPort int16) int16 {
	val, err := strconv.ParseInt(s, 10, 17)
	if err != nil {
		// fmoption.Printf("err %v", err)
		// handle the error appropriately; here we return 0
		return defaultPort
	}
	return int16(val)
}

func isIPOnly(s string) bool {
	return net.ParseIP(s) != nil
}

func getOneOf(dic map[string]string, headers ...string) (string, error) {
	for _, h := range headers {
		if str, ok := dic[h]; ok {
			return str, nil
		}
	}
	return "", fmt.Errorf("not found")
}

func getOneOfN(dic map[string]string, defaultval string, headers ...string) string {
	for _, h := range headers {
		if str, ok := dic[normalizeStr(h)]; ok {
			return str
		}
	}
	return defaultval
}
