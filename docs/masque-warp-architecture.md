# MASQUE and WARP-MASQUE Architecture (hiddify-core)

## Scope
This document defines the target architecture for adding two **new** endpoints in `hiddify-core`:

- `masque` (generic MASQUE endpoint)
- `warp_masque` (Cloudflare WARP-compatible endpoint on the same MASQUE core)

Legacy `warp` stays unchanged and runs in parallel.

## Goals
- Add MASQUE transport to sing-box data plane in endpoint form.
- Reuse one MASQUE core across `masque` and `warp_masque`.
- Keep strict no-break behavior for legacy `warp`.
- Support MASQUE chaining model (single-hop and multi-hop policy model).
- Preserve sing-box semantics and lifecycle patterns.

## Non-Goals
- Replacing or refactoring legacy `protocol/wireguard/endpoint_warp.go`.
- Changing client/panel behavior in this phase.
- Implementing all runtime chaining optimizations in the first PR set.

## Current Baseline (Relevant)

### Endpoint contract
`adapter.Endpoint` is lifecycle + outbound behavior:

```10:15:hiddify-core/hiddify-sing-box/adapter/endpoint.go
type Endpoint interface {
	Lifecycle
	Type() string
	Tag() string
	Outbound
}
```

### Legacy WARP semantics (authorregistration parity source)
Current `warp` endpoint performs profile acquisition and registration logic inside endpoint path:

- `GetWarpProfileDialer` calls `api.GetProfile(...)` when id/token exist.
- Else it calls `api.CreateProfileLicense(...)`, which creates device profile and optional license update.

```182:189:hiddify-core/hiddify-sing-box/protocol/wireguard/endpoint_warp.go
func GetWarpProfileDialer(ctx context.Context, dialer N.Dialer, profile *option.WARPProfile) (*cloudflare.CloudflareProfile, error) {
	api := cloudflare.NewCloudflareApiDetour(dialer)
	if profile.AuthToken != "" && profile.ID != "" {
		return api.GetProfile(ctx, profile.AuthToken, profile.ID)
	} else {
		return api.CreateProfileLicense(ctx, profile.PrivateKey, profile.License)
	}
}
```

This means **registration is embedded in endpoint/core path today**.

### Endpoint registration pattern
WireGuard and legacy WARP endpoints are registered under endpoint registry:

```15:18:hiddify-core/hiddify-sing-box/include/wireguard.go
func registerWireGuardEndpoint(registry *endpoint.Registry) {
	wireguard.RegisterEndpoint(registry)
	wireguard.RegisterWARPEndpoint(registry)
}
```

## Architecture Decision Summary

1. Add **new endpoint types** (`masque`, `warp_masque`) without touching legacy `warp`.
2. Build shared runtime in `common/masque` + `transport/masque`.
3. Keep WARP compatibility in `warp_masque` only.
4. By parity rule with current semantics, implement **embedded registration flow** in `warp_masque` endpoint path.
5. Keep config and runtime fully parallel: old and new endpoints can coexist.

## Target Topology

```mermaid
flowchart LR
  subgraph cfg [Config Layer]
    v2cfg[v2 parser and builder]
    legacyWarpCfg[legacy warp config]
    masqueCfg[masque config]
    warpMasqueCfg[warp_masque config]
  end

  subgraph endpointLayer [Endpoint Layer]
    legacyWarpEp[legacy warp endpoint unchanged]
    masqueEp[masque endpoint]
    warpMasqueEp[warp_masque endpoint]
  end

  subgraph coreLayer [Reusable MASQUE Core]
    masqueCore[common/masque session core]
    masqueTransport[transport/masque h3 quic]
    chainPolicy[chain graph and policy engine]
    warpControl[warp control-plane adapter]
  end

  subgraph dataplane [Sing-box Data Plane]
    routeCore[route and prematch]
    tunInbound[tun inbound packet path]
  end

  v2cfg --> legacyWarpCfg
  v2cfg --> masqueCfg
  v2cfg --> warpMasqueCfg

  legacyWarpCfg --> legacyWarpEp
  masqueCfg --> masqueEp
  warpMasqueCfg --> warpMasqueEp

  masqueEp --> masqueCore
  warpMasqueEp --> masqueCore
  masqueCore --> masqueTransport
  masqueCore --> chainPolicy
  warpMasqueEp --> warpControl

  legacyWarpEp --> routeCore
  masqueEp --> routeCore
  warpMasqueEp --> routeCore
  masqueEp --> tunInbound
```

## Layered Design

## 1) `common/masque`
Responsibilities:
- Session state machine (`init`, `connecting`, `ready`, `degraded`, `reconnecting`, `closed`).
- Capability model:
  - `connect_udp`
  - `connect_ip`
  - `auto`
- Chain graph model (nodes/hops/egress policy), independent from wire implementation.
- Retry, backoff, health probing, failover policy.
- Error taxonomy normalized for endpoint layer.

Must not import sing-box router internals.

## 2) `transport/masque`
Responsibilities:
- HTTP/3 + QUIC transport handling.
- MASQUE methods:
  - CONNECT-UDP
  - CONNECT-IP
- Datagrams/streams, flow control, keepalive, path migration hooks.
- Fallback policy hooks (`h3`, optional `h2/tcp` where supported by policy).

Dependency boundary:
- Library-specific APIs stay here (`quic-go/masque-go`, `connect-ip-go`).
- Endpoint/config layer receives abstract interfaces only.

## 3) `protocol/masque`

### `endpoint.go` (`type: masque`)
Responsibilities:
- Implements `adapter.Endpoint` lifecycle:
  - `Start`
  - `Close`
  - `DialContext`
  - `ListenPacket`
- Integrates with route/TUN semantics through endpoint/outbound interfaces.
- Uses chain policy and transport mode from config.

### `endpoint_warp_masque.go` (`type: warp_masque`)
Responsibilities:
- Reuses same MASQUE core and transport.
- Adds Cloudflare-specific control-plane behavior.
- Keeps WARP-compatible config and bootstrap semantics.

Important:
- No references to legacy `endpoint_warp.go` path.
- Shared code only through `common/masque` and dedicated cloudflare adapter package.

## Control-plane and Registration Policy

## Parity Decision (resolved)
Rule: if legacy WARP has embedded registration in endpoint path, `warp_masque` must keep embedded registration semantics.

Result: **embedded registration is required** for `warp_masque` in core, because current `warp` does it via endpoint flow.

## `warp_masque` control-plane behavior
- If id/token are provided, attempt profile fetch/refresh.
- If not provided, perform registration/create profile flow.
- Cache profile/state through core cache mechanisms, with explicit versioned schema.
- Support detour-aware control-plane requests (consistent with current outbound detour semantics).

## Config Model (Draft)

## Endpoint `masque`
- Generic fields:
  - `server`
  - `server_port`
  - `transport_mode`: `connect_udp | connect_ip | auto`
  - `chain`: optional hop list and selection policy
  - `detour`
  - `mtu` / `udp_timeout` / workers (where applicable)

## Endpoint `warp_masque`
- WARP-focused fields:
  - `profile.id`
  - `profile.auth_token`
  - `profile.license`
  - `profile.private_key` (if required by control-plane flavor)
  - `detour`
  - optional explicit server override
  - `transport_mode` with safe defaults for Cloudflare compatibility

## Chaining Model
- First-class chain graph in config and core.
- Must support:
  - single-hop (default)
  - explicit multi-hop chain
- Routing policy binds traffic classes to chain profiles.
- Endpoint API remains stable even if runtime chain scheduling evolves.

## Data Plane Integration Notes
- Endpoint must behave as outbound-compatible transport for route selection.
- Tun overlay path uses endpoint `ListenPacket` behavior; MASQUE endpoint must provide robust packet mode.
- PreMatch-driven policy remains unchanged from router perspective.

## Compatibility and Rollout
- Legacy `warp` untouched.
- New endpoints added side-by-side.
- No aliasing or hidden migration from `warp` to `warp_masque`.
- Feature gates for new endpoint types allowed, but default behavior of legacy path must not change.

## Implementation Status (M2 hardening)
- Added endpoint types, registry wiring and build-tag stubs:
  - `masque`
  - `warp_masque`
- Added runtime stateful core (`common/masque`) with readiness derived from session start result.
- Added transport contract hardening (`transport/masque`) with mode-aware `M2ClientFactory` and stable `ClientFactory/ClientSession` boundary.
- Added dedicated Cloudflare control adapter for `warp_masque` bootstrap parity, isolating provider-specific logic from protocol endpoint lifecycle.
- Added chain graph validation in runtime preparation (`via` references, duplicate tags, cycle guard) for deterministic single-hop/multi-hop execution order.

Current M2 limits:
- Backend still uses a conservative foundation session implementation; full RFC-level CONNECT-UDP/CONNECT-IP wire behavior remains an incremental transport task.
- Chain execution currently focuses on deterministic graph validation and ordering; advanced failover scheduling remains follow-up work.

## Testing Strategy

## Contract Tests
- Freeze current `warp` behavior snapshots (startup, profile bootstrap, readiness, error mapping).
- Verify no regression in legacy path.

## Endpoint Integration Tests
- `masque`: dial/listen, connect modes, route policy.
- `warp_masque`: registration bootstrap, token reuse path, detour path, reconnect.

## Chaining Tests
- Config validation for chain graph.
- Single-hop and multi-hop route binding.
- Failure propagation and failover behavior.

## E2E
- Route + tun packet flows.
- Fallback and reconnect scenarios.
- Parallel operation with legacy `warp`.

## Risks and Mitigations
- Cloudflare behavior can diverge from RFC details.
  - Mitigation: isolate cloudflare adapter; keep transport generic.
- Chaining complexity can delay runtime maturity.
  - Mitigation: stabilize API/model now, phase runtime optimizations.
- Cache/schema drift.
  - Mitigation: versioned cache format for `warp_masque` profile state.

## Implementation Work Packages
1. Add constants/options for `masque` and `warp_masque`.
2. Implement `common/masque` core contracts.
3. Implement `transport/masque` abstraction + baseline runtime.
4. Implement `protocol/masque/endpoint.go`.
5. Implement `protocol/masque/endpoint_warp_masque.go` with embedded registration parity.
6. Add config parser/builder support for new endpoint types.
7. Add tests (contract/integration/e2e/chaining).
8. Document operator guidance and known limits.

