// Package awg implements the AmneziaWG endpoint transport (amneziawg-go), aligned with
// package wireguard where the underlying library allows.
//
// Architecture (vs wireguard transport):
//
//   - Same endpoint shape: TUN selection (see device.go), NAT wrapper when needed, amnezia device,
//     allowed-IP lookup for routing helpers.
//
// Parity with transport/wireguard (intentional differences):
//
//   - Obfuscation: AWG uses Amnezia IPC keys (jc, jmin, jmax, s1-s4, h1-h4, i1-i5) in buildIpcConfig.
//     WireGuard uses hiddify NoiseOptions and a different device.NewDevice signature.
//     Transport/cookie padding prepends random bytes before the WireGuard frame; the device passes a
//     matching Send offset so `reserved` applies to the frame type byte, not to the UDP byte 0.
//
//   - TUN matrix (!System): same as WireGuard — sing-tun gvisor userspace stack (device_stack.go), not
//     amneziawg-go/tun/netstack. Handler and UDPTimeout wire TCP/UDP/ICMP like wireguard/device_stack.go.
//
//   - TUN matrix (System): kernel sing-tun like WireGuard’s system path. When sing-tun is built with gvisor,
//     WireGuard can use transport/wireguard/device_system_stack.go (kernel TUN + overlay via device.InputPacket).
//     Upstream amneziawg-go does not expose InputPacket; AWG keeps kernel-only system TUN in that case (device.go).
//
//   - Bind: non-listener path uses newBind (dialer) with the same Warp-style peer
//     `reserved` bytes (relative to conn.Bind Send offset: payload[offset+1:offset+4]) as
//     transport/wireguard ClientBind. WireGuardListener uses awgconn.NewStdNetBind with
//     WireGuardControl(), matching transport/wireguard.
//
//   - Engine: device.NewDevice(tun, bind, logger) has no context/workers/prealloc parameters.
//     EndpointOptions may carry Workers, PreallocatedBuffersPerPool, and protocol Noise for JSON
//     parity with WireGuardEndpointOptions; they are not passed into amneziawg-go. The
//     wireguard transport likewise does not wire Noise/PreallocatedBuffersPerPool into its
//     device constructor in this fork—only Workers go to device.NewDevice.
//
//   - Close: awgdevice.Device.Close closes the tun device; do not close the tun adapter again from outside.
//
// Symmetry audit matrix (WG reference vs AWG):
//
//   - Linux, system TUN (P0):
//     WG: batch-aware path (LinuxTUN BatchRead/BatchWrite + dynamic BatchSize) with GSO enabled.
//     AWG: now mirrors this behavior in transport layer to avoid ErrTooManySegments drops under GSO.
//
//   - Linux, userspace stack (P1):
//     WG and AWG both use sing-tun gvisor stack with equivalent lifecycle/dial/listen semantics.
//
//   - with_gvisor + system=true hybrid (P1, accepted asymmetry):
//     WG supports kernel TUN + gvisor overlay via device.InputPacket; AWG keeps kernel-only system TUN
//     because upstream amneziawg-go does not expose equivalent InputPacket API.
//
//   - Windows/Android low-level tun in replace/*wg-go (P1):
//     Implementations are largely mirrored; transport layer must preserve BatchSize-aware behavior where
//     supported and keep single-packet fallback elsewhere.
//
//   - Android queue constants (P2):
//     AWG follows WG MaxSegmentSize constraints to avoid larger-than-necessary segment buffering pressure
//     on memory-constrained devices.

package awg
