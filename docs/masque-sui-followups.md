# s-ui Follow-ups for MASQUE and WARP-MASQUE

This note tracks required `vendor/s-ui` updates after core endpoint types `masque` and `warp_masque` are added.

## Scope
Core now defines endpoint types in runtime registry, but panel/API/subscription layers still need explicit support before operators can manage these types from UI.

## Required follow-ups in `vendor/s-ui`

## 1) Endpoint type model and UI forms
- Update endpoint type enums/default payloads:
  - `vendor/s-ui/frontend/src/types/endpoints.ts`
- Add UI form components and routing for new types:
  - `vendor/s-ui/frontend/src/layouts/modals/Endpoint.vue`
  - likely new components under `vendor/s-ui/frontend/src/components/protocols/`

## 2) Backend endpoint save/normalize logic
- Extend endpoint save/validation dispatch:
  - `vendor/s-ui/service/endpoints.go`
- Decide which fields are UI-only and must be stripped from runtime JSON for new types:
  - `vendor/s-ui/database/model/endpoints.go`

## 3) Runtime registration alignment
- Ensure `vendor/s-ui/core/register.go` remains aligned with core endpoint registry and supports new types in generated runtime config.

## 4) Subscription and patch pipeline
- Add JSON subscription patch support for new types where needed:
  - `vendor/s-ui/sub/jsonService.go`
  - new patchers similar to `wg_json_patch.go` / `awg_json_patch.go` if route/tun augmentation is required
- Validate behavior in `clashService.go` and `subToJson.go` for unknown/new endpoint types.

## 5) API and compatibility rules
- Decide whether legacy `warp` stays remapped to wireguard in panel serialization while `warp_masque` remains a distinct type.
- Keep no-break behavior for existing clients and subscriptions.

## 6) New runtime expectations from hardened core
- `masque` now has runtime-backed lifecycle/readiness and active dial/listen path.
- `masque` now supports endpoint `mode=client|server` shape in core options.
- `warp_masque` now performs parity bootstrap in endpoint path (Cloudflare profile fetch/create behavior).
- `fallback_policy` now defaults to strict transport semantics; direct fallback is explicit opt-in.
- `tls_server_name` and `insecure` are now explicit transport controls for MASQUE client paths.
- `transport_mode` and `hop_policy/hops` are validated in core; panel forms should enforce the same constraints client-side to avoid invalid payloads.
- For `hop_policy=single`, server is required.
- For `hop_policy=chain`, at least one hop is required and each hop must contain `server`.
- `hops[].via` is supported for explicit chain graph links; backend rejects unknown references and cycles.
- `warp_masque` bootstrap control-plane is isolated in dedicated adapter logic; panel should keep parity knobs (`id/auth_token/license/private_key/recreate/detour`) explicit and versionable.
- `warp_masque` now has endpoint-side cache-aware server resolution (reuse path) and explicit `recreate` bypass behavior; panel should surface these semantics without implicit remapping.
- `warp_masque` cache format is versioned and TTL-aware in core; panel migration code should treat cache as implementation detail and rely on profile fields as source of truth.
- `warp_masque` startup is async by design; UI should treat initial non-ready state as bootstrap phase and show control-plane diagnostics when available.
- New template fields are available for core transport mapping:
  - `template_udp`
  - `template_ip`
  Panel/backend should expose or safely default these fields.

## Rollout recommendation
1. Ship core endpoint support first (done in current step).
2. Add panel/backend type awareness behind UI gating.
3. Add subscription output support.
4. Enable default creation in UI only after e2e tests pass.

## 7) Ready-to-implement `vendor/s-ui` checklist (next increment)
- Add `masque` / `warp_masque` type-safe schemas in frontend type layer and backend endpoint models.
- Add form-level validation parity for `transport_mode`, `hop_policy`, `hops[].server`, `hops[].via`.
- Add backend serialization guards to preserve legacy `warp` untouched and keep `warp_masque` standalone.
- Add subscription patch pipeline coverage for new endpoint types and negative tests for invalid chain graphs.
- Add integration fixture generation for `masque(single)`, `masque(chain)`, `warp_masque(reuse/create/recreate)` presets.
- Add negative fixtures for unsupported chain topologies (multiple root hops) to mirror runtime guardrails.
- Add fixture coverage for hop failover order semantics so panel presets match runtime behavior during degraded upstream hops.
- Add a smoke/perf pipeline entry that references `hiddify-core/docs/masque-perf-gates.md` for operational regression tracking.

