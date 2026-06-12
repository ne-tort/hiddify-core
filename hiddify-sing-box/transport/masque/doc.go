// Package masque implements the MASQUE client transport (CONNECT-stream, CONNECT-IP, CONNECT-UDP)
// for sing-box over HTTP/2 and HTTP/3.
//
// Refactor map, layer checklists, and target package layout live in the hiddify-app repo:
// docs/masque/layers/ (see AGENTS.md at repo root).
//
// Intended decomposition (in progress):
//   - session/     coreSession, dial, lifecycle
//   - h2/, h3/     HTTP transport
//   - stream/      TCP bidi CONNECT-stream dataplane
//   - connectip/   CONNECT-IP packet plane + gVisor netstack
//   - connectudp/  CONNECT-UDP
package masque
