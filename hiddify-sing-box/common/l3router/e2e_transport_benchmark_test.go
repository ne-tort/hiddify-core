package l3router

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net/netip"
	"sync/atomic"
	"testing"
)

// TransportProfile models a protocol-specific payload transformation on top of l3router.
// It is intentionally synthetic for benchmark repeatability and easy extension.
type TransportProfile interface {
	Name() string
	Encode(payload []byte, packetID uint64) ([]byte, error)
	Decode(frame []byte, packetID uint64) ([]byte, error)
}

type plainL3RouterProfile struct{}

func (p *plainL3RouterProfile) Name() string { return "plain_l3router_baseline" }
func (p *plainL3RouterProfile) Encode(payload []byte, _ uint64) ([]byte, error) {
	return payload, nil
}
func (p *plainL3RouterProfile) Decode(frame []byte, _ uint64) ([]byte, error) {
	return frame, nil
}

// vlessRealityVisionSynthetic emulates per-packet framing + authenticated encryption.
// This is not wire-compatible VLESS/REALITY; it only approximates protocol overhead.
type vlessRealityVisionSynthetic struct {
	aead cipher.AEAD
}

func newVLESSRealityVisionSynthetic() (*vlessRealityVisionSynthetic, error) {
	key := []byte("0123456789abcdef0123456789abcdef")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &vlessRealityVisionSynthetic{aead: aead}, nil
}

func (p *vlessRealityVisionSynthetic) Name() string { return "vless_reality_vision_synthetic" }

func (p *vlessRealityVisionSynthetic) Encode(payload []byte, packetID uint64) ([]byte, error) {
	nonce := make([]byte, p.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], packetID)
	// 8 bytes synthetic "vision header" + encrypted payload.
	frame := make([]byte, 8)
	binary.BigEndian.PutUint32(frame[:4], 0x5649534e) // "VISN"
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(payload)))
	frame = p.aead.Seal(frame, nonce, payload, frame[:8])
	return frame, nil
}

func (p *vlessRealityVisionSynthetic) Decode(frame []byte, packetID uint64) ([]byte, error) {
	if len(frame) < 8+p.aead.Overhead() {
		return nil, fmt.Errorf("short frame")
	}
	header := frame[:8]
	nonce := make([]byte, p.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], packetID)
	payload, err := p.aead.Open(nil, nonce, frame[8:], header)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// hysteria2Synthetic emulates udp-oriented encrypted framing with extra metadata checksum.
type hysteria2Synthetic struct {
	aead cipher.AEAD
}

func newHysteria2Synthetic() (*hysteria2Synthetic, error) {
	key := []byte("hy2-hy2-hy2-hy2-hy2-hy2-hy2-hy2-")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &hysteria2Synthetic{aead: aead}, nil
}

func (p *hysteria2Synthetic) Name() string { return "hy2_synthetic" }

func (p *hysteria2Synthetic) Encode(payload []byte, packetID uint64) ([]byte, error) {
	nonce := make([]byte, p.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], packetID)
	frame := make([]byte, 12)
	binary.BigEndian.PutUint32(frame[:4], 0x48593230) // "HY20"
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(payload)))
	binary.BigEndian.PutUint32(frame[8:12], crc32.ChecksumIEEE(payload))
	frame = p.aead.Seal(frame, nonce, payload, frame[:12])
	return frame, nil
}

func (p *hysteria2Synthetic) Decode(frame []byte, packetID uint64) ([]byte, error) {
	if len(frame) < 12+p.aead.Overhead() {
		return nil, fmt.Errorf("short hy2 frame")
	}
	header := frame[:12]
	nonce := make([]byte, p.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], packetID)
	payload, err := p.aead.Open(nil, nonce, frame[12:], header)
	if err != nil {
		return nil, err
	}
	wantCRC := binary.BigEndian.Uint32(header[8:12])
	gotCRC := crc32.ChecksumIEEE(payload)
	if wantCRC != gotCRC {
		return nil, fmt.Errorf("hy2 crc mismatch")
	}
	return payload, nil
}

// tuicSynthetic emulates framed payload with lightweight token and integrity tag.
type tuicSynthetic struct {
	aead cipher.AEAD
	mac  []byte
}

func newTUICSynthetic() (*tuicSynthetic, error) {
	key := []byte("0123456789abcdef0123456789abcdef")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &tuicSynthetic{
		aead: aead,
		mac:  []byte("tuic-mac-key"),
	}, nil
}

func (p *tuicSynthetic) Name() string { return "tuic_synthetic" }

func (p *tuicSynthetic) Encode(payload []byte, packetID uint64) ([]byte, error) {
	nonce := make([]byte, p.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], packetID)
	tokenRaw := make([]byte, 8)
	binary.BigEndian.PutUint64(tokenRaw, packetID^0xa5a5a5a5a5a5a5a5)
	token := base64.RawURLEncoding.EncodeToString(tokenRaw)
	if len(token) < 11 {
		return nil, fmt.Errorf("short tuic token")
	}
	header := make([]byte, 15)
	copy(header[:11], token[:11])
	binary.BigEndian.PutUint32(header[11:15], uint32(len(payload)))
	frame := p.aead.Seal(append([]byte{}, header...), nonce, payload, header)
	h := hmac.New(sha256.New, p.mac)
	h.Write(frame)
	tag := h.Sum(nil)[:8]
	frame = append(frame, tag...)
	return frame, nil
}

func (p *tuicSynthetic) Decode(frame []byte, packetID uint64) ([]byte, error) {
	if len(frame) < 15+p.aead.Overhead()+8 {
		return nil, fmt.Errorf("short tuic frame")
	}
	h := hmac.New(sha256.New, p.mac)
	h.Write(frame[:len(frame)-8])
	wantTag := h.Sum(nil)[:8]
	gotTag := frame[len(frame)-8:]
	if !hmac.Equal(wantTag, gotTag) {
		return nil, fmt.Errorf("tuic tag mismatch")
	}
	body := frame[:len(frame)-8]
	header := body[:15]
	nonce := make([]byte, p.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], packetID)
	payload, err := p.aead.Open(nil, nonce, body[15:], header)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

// mieruSynthetic approximates Mieru-style packet-over-stream framing (length prefix + AEAD).
// Not wire-compatible with github.com/enfein/mieru; mirrors sing-box protocol/mieru layering intent.
type mieruSynthetic struct {
	aead cipher.AEAD
}

func newMieruSynthetic() (*mieruSynthetic, error) {
	key := []byte("0123456789abcdef0123456789abcdef")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &mieruSynthetic{aead: aead}, nil
}

func (p *mieruSynthetic) Name() string { return "mieru_synthetic" }

func (p *mieruSynthetic) Encode(payload []byte, packetID uint64) ([]byte, error) {
	nonce := make([]byte, p.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], packetID)
	// 16-byte stream chunk header: magic "MI53", length, seq low 32 bits.
	frame := make([]byte, 16)
	copy(frame[:4], []byte("MI53"))
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(payload)))
	binary.BigEndian.PutUint64(frame[8:16], packetID)
	frame = p.aead.Seal(frame, nonce, payload, frame[:16])
	return frame, nil
}

func (p *mieruSynthetic) Decode(frame []byte, packetID uint64) ([]byte, error) {
	if len(frame) < 16+p.aead.Overhead() {
		return nil, fmt.Errorf("short mieru frame")
	}
	header := frame[:16]
	nonce := make([]byte, p.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], packetID)
	payload, err := p.aead.Open(nil, nonce, frame[16:], header)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func syntheticTransportProfiles(b *testing.B) []TransportProfile {
	vless, err := newVLESSRealityVisionSynthetic()
	if err != nil {
		b.Fatalf("create vless profile: %v", err)
	}
	hy2, err := newHysteria2Synthetic()
	if err != nil {
		b.Fatalf("create hy2 profile: %v", err)
	}
	tuic, err := newTUICSynthetic()
	if err != nil {
		b.Fatalf("create tuic profile: %v", err)
	}
	mieru, err := newMieruSynthetic()
	if err != nil {
		b.Fatalf("create mieru profile: %v", err)
	}
	return []TransportProfile{
		&plainL3RouterProfile{},
		vless,
		hy2,
		tuic,
		mieru,
	}
}

func BenchmarkL3RouterEndToEndSyntheticTransport(b *testing.B) {
	profiles := syntheticTransportProfiles(b)
	for _, p := range profiles {
		profile := p
		b.Run(profile.Name(), func(b *testing.B) {
			benchEndToEndForProfile(b, profile)
		})
	}
}

func BenchmarkL3RouterEndToEndSyntheticTransportParallel(b *testing.B) {
	profiles := syntheticTransportProfiles(b)
	for _, p := range profiles {
		profile := p
		b.Run(profile.Name(), func(b *testing.B) {
			benchEndToEndParallelForProfile(b, profile)
		})
	}
}

func BenchmarkL3RouterEndToEndSyntheticTransportManyFlowsOneOwnerParallel(b *testing.B) {
	profiles := syntheticTransportProfiles(b)
	for _, p := range profiles {
		profile := p
		b.Run(profile.Name(), func(b *testing.B) {
			benchEndToEndManyFlowsOneOwnerParallelForProfile(b, profile)
		})
	}
}

func BenchmarkSyntheticTransportOnly(b *testing.B) {
	profiles := syntheticTransportProfiles(b)
	for _, p := range profiles {
		profile := p
		b.Run(profile.Name(), func(b *testing.B) {
			benchTransportOnlyForProfile(b, profile)
		})
	}
}

func benchEndToEndForProfile(b *testing.B, profile TransportProfile) {
	engine := NewMemEngine()
	engine.SetPacketFilter(false)
	engine.UpsertRoute(Route{
		PeerID:          1,
		User:            "client-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.10.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.10.1.0/24")},
	})
	engine.UpsertRoute(Route{
		PeerID:          2,
		User:            "client-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.10.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.10.2.0/24")},
	})
	ipPacket := makeBenchmarkIPv4UDPPacket(benchmarkPacketSize, 10, 10, 1, 2, 10, 10, 2, 2)

	b.ReportAllocs()
	b.SetBytes(int64(len(ipPacket)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		packetID := uint64(i + 1)
		clientAFrame, err := profile.Encode(ipPacket, packetID)
		if err != nil {
			b.Fatalf("%s encode ingress: %v", profile.Name(), err)
		}
		ingressPayload, err := profile.Decode(clientAFrame, packetID)
		if err != nil {
			b.Fatalf("%s decode ingress: %v", profile.Name(), err)
		}
		decision := engine.HandleIngressPeer(ingressPayload, PeerID(1))
		if decision.Action != ActionForward || decision.EgressPeerID != PeerID(2) {
			b.Fatalf("unexpected decision: %+v", decision)
		}
		serverEgressFrame, err := profile.Encode(ingressPayload, packetID)
		if err != nil {
			b.Fatalf("%s encode egress: %v", profile.Name(), err)
		}
		clientBPayload, err := profile.Decode(serverEgressFrame, packetID)
		if err != nil {
			b.Fatalf("%s decode egress: %v", profile.Name(), err)
		}
		if len(clientBPayload) != len(ipPacket) {
			b.Fatalf("payload length mismatch: got %d want %d", len(clientBPayload), len(ipPacket))
		}
	}
}

func benchTransportOnlyForProfile(b *testing.B, profile TransportProfile) {
	ipPacket := makeBenchmarkIPv4UDPPacket(benchmarkPacketSize, 10, 10, 1, 2, 10, 10, 2, 2)

	b.ReportAllocs()
	b.SetBytes(int64(len(ipPacket)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		packetID := uint64(i + 1)
		clientAFrame, err := profile.Encode(ipPacket, packetID)
		if err != nil {
			b.Fatalf("%s encode client A: %v", profile.Name(), err)
		}
		serverDecoded, err := profile.Decode(clientAFrame, packetID)
		if err != nil {
			b.Fatalf("%s decode server side: %v", profile.Name(), err)
		}
		serverEgressFrame, err := profile.Encode(serverDecoded, packetID)
		if err != nil {
			b.Fatalf("%s encode client B: %v", profile.Name(), err)
		}
		clientBPayload, err := profile.Decode(serverEgressFrame, packetID)
		if err != nil {
			b.Fatalf("%s decode client B: %v", profile.Name(), err)
		}
		if len(clientBPayload) != len(ipPacket) {
			b.Fatalf("payload length mismatch: got %d want %d", len(clientBPayload), len(ipPacket))
		}
	}
}

func benchEndToEndParallelForProfile(b *testing.B, profile TransportProfile) {
	engine := NewMemEngine()
	engine.SetPacketFilter(false)
	engine.UpsertRoute(Route{
		PeerID:          1,
		User:            "client-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.10.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.10.1.0/24")},
	})
	engine.UpsertRoute(Route{
		PeerID:          2,
		User:            "client-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.10.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.10.2.0/24")},
	})
	ipPacket := makeBenchmarkIPv4UDPPacket(benchmarkPacketSize, 10, 10, 1, 2, 10, 10, 2, 2)

	var packetIndex uint64
	var errorCount uint64

	b.ReportAllocs()
	b.SetBytes(int64(len(ipPacket)))
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			packetID := atomic.AddUint64(&packetIndex, 1)
			clientAFrame, err := profile.Encode(ipPacket, packetID)
			if err != nil {
				atomic.AddUint64(&errorCount, 1)
				continue
			}
			ingressPayload, err := profile.Decode(clientAFrame, packetID)
			if err != nil {
				atomic.AddUint64(&errorCount, 1)
				continue
			}
			decision := engine.HandleIngressPeer(ingressPayload, PeerID(1))
			if decision.Action != ActionForward || decision.EgressPeerID != PeerID(2) {
				atomic.AddUint64(&errorCount, 1)
				continue
			}
			serverEgressFrame, err := profile.Encode(ingressPayload, packetID)
			if err != nil {
				atomic.AddUint64(&errorCount, 1)
				continue
			}
			clientBPayload, err := profile.Decode(serverEgressFrame, packetID)
			if err != nil || len(clientBPayload) != len(ipPacket) {
				atomic.AddUint64(&errorCount, 1)
			}
		}
	})
	b.StopTimer()

	b.ReportMetric(float64(errorCount), "errors")
	b.ReportMetric(float64(errorCount)/float64(b.N), "error/op")
}

func benchEndToEndManyFlowsOneOwnerParallelForProfile(b *testing.B, profile TransportProfile) {
	engine := NewMemEngine()
	engine.SetPacketFilter(false)
	engine.UpsertRoute(Route{
		PeerID:          1,
		User:            "client-a",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.10.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.10.1.0/24")},
	})
	engine.UpsertRoute(Route{
		PeerID:          2,
		User:            "client-b",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.10.2.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.10.2.0/24")},
	})
	const flowCount = 64
	flowPackets := make([][]byte, flowCount)
	for i := 0; i < len(flowPackets); i++ {
		pkt := makeBenchmarkIPv4UDPPacket(benchmarkPacketSize, 10, 10, 1, 2, 10, 10, 2, 2)
		// Many independent flows from one owner subnet to emulate fairness pressure.
		pkt[15] = byte((i % 200) + 1)
		flowPackets[i] = pkt
	}

	var packetIndex uint64
	var errorCount uint64

	b.ReportAllocs()
	b.SetBytes(int64(len(flowPackets[0])))
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			packetID := atomic.AddUint64(&packetIndex, 1)
			pkt := flowPackets[packetID%flowCount]
			clientAFrame, err := profile.Encode(pkt, packetID)
			if err != nil {
				atomic.AddUint64(&errorCount, 1)
				continue
			}
			ingressPayload, err := profile.Decode(clientAFrame, packetID)
			if err != nil {
				atomic.AddUint64(&errorCount, 1)
				continue
			}
			decision := engine.HandleIngressPeer(ingressPayload, PeerID(1))
			if decision.Action != ActionForward || decision.EgressPeerID != PeerID(2) {
				atomic.AddUint64(&errorCount, 1)
				continue
			}
			serverEgressFrame, err := profile.Encode(ingressPayload, packetID)
			if err != nil {
				atomic.AddUint64(&errorCount, 1)
				continue
			}
			clientBPayload, err := profile.Decode(serverEgressFrame, packetID)
			if err != nil || len(clientBPayload) != len(pkt) {
				atomic.AddUint64(&errorCount, 1)
			}
		}
	})
	b.StopTimer()

	b.ReportMetric(float64(errorCount), "errors")
	b.ReportMetric(float64(errorCount)/float64(b.N), "error/op")
}
