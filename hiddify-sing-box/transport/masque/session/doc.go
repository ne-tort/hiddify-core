// Package session holds MASQUE client session types, factories, and core session state (phase F).
//
// # Lock contract (CoreSession)
//
// | Mutex | Protects | Notes |
// |-------|----------|-------|
// | Mu | UDPClient, H2UDPTransport ref (close via H2UDPMu), IPConn, IPHTTP, IPHTTPConn, IPHTTPH2Upload, TCPHTTP, TCPRoundTripper, TemplateUDP/IP/TCP, TCPNetstack, ConnectIPIngress*, ConnectIPPMTUState + datagram ceiling fields, HTTPLayerFallback pivot, hop template rebuild | Primary session lock; prefer *LockedAssumeMu helpers when already held |
// | H2UDPMu | H2UDPTransport pool (CONNECT-UDP/IP on H2) | Teardown via CloseAllH2ClientTransports / resetH2UDPTransportLockedAssumeMu while holding Mu |
// | H2ConnectStreamMu | H2ConnectStreamTransport pool (CONNECT-stream on H2) | Same pattern as H2UDPMu |
// | UDPHTTPLayer (atomic.Value) | Effective overlay "h2"/"h3" | Read without Mu; writes during fallback pivot hold Mu |
// | HTTPFallbackConsumed (atomic.Bool) | One-shot http_layer_fallback latch | CAS under Mu in TryHTTPFallbackSwitchLockedAssumeMu |
// | ConnectIPIngressOnce (sync.Once) | Lazy ConnectIPIngress singleton | Do body may read Mu-protected fields; ingress host callbacks take Mu independently |
// | ConnectIPTCPInstallInflight (atomic.Int32) | In-flight CONNECT-IP TCP netstack install | Lock-free counter; paired with ingress lifecycle |
// | IngressTCPNetstack (atomic.Pointer) | Pre-TCP netstack handoff | Set/cleared during ingress install and LifecycleClose |
// | ConnectIPPMTUState + ceiling ints | UDP payload bounds for CONNECT-IP bridge | ConnectIPPMTUState has internal Mu; session fields updated under Mu during open |
// | IPHTTPH2Upload | H2 CONNECT-IP ingress ACK wake writer | Set/cleared under Mu on reuse/dial/teardown |
// | TCPRoundTripper | Optional per-session H2 round-tripper override | Read via getTCPRoundTripper while Mu held during open-dial |
//
// Open-dial Mu rule: OpenIPSessionLocked and dialConnectIPTCP hold Mu across network dial
// (DialConnectIPOnCurrentHopLocked → cip.DialOnCurrentHop). Do not acquire Mu in helpers invoked
// from that path (e.g. getTCPRoundTripper) or from ingress deliver (IngressTCPNetstackForInject reads
// IngressTCPNetstack atomic only; typed netstack is published under Mu in AttachTCPNetstack).
//
// Lock order: never acquire Mu while holding H2UDPMu or H2ConnectStreamMu. LifecycleClose takes Mu first,
// snapshots overlay refs, releases Mu, then closes H2 pools under their dedicated mutexes.
package session
