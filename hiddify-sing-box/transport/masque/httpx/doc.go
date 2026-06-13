// Package httpx defines the MASQUE HTTP overlay (H2/H3) abstraction used by coreSession.
//
// HTTPLayer is deprecated for production: real dial/listen paths live in transport/masque bridges.
// Use HookLayer + httpx.BindHookLayer in tests. IsLayerSwitchableFailure is the live classifier for
// http_layer_fallback (mirrors protocol/masque connect_http_auth sentinels).
package httpx
