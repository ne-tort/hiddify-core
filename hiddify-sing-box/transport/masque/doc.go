// Package masque implements the MASQUE client transport (CONNECT-stream, CONNECT-IP, CONNECT-UDP)
// for sing-box over HTTP/2 and HTTP/3.
//
// Refactor map, layer checklists, and target package layout live in the hiddify-app repo:
// docs/masque/layers/ (see AGENTS.md at repo root).
//
// Package layout (see docs/masque/layers/TARGET-PACKAGES.md):
//   session/, httpx/  — dial, lifecycle, HTTP layer switch
//   h2/, h3/          — HTTP transport
//   stream/           — CONNECT-stream dataplane
//   connectip/        — CONNECT-IP client packet plane
//   forwarder/        — TCP/UDP termination (shared with server)
//   connectudp/       — CONNECT-UDP
package masque
