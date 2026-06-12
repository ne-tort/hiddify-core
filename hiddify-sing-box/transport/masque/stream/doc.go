// Package stream implements CONNECT-stream (RFC 8441 / 9114) TCP bidi tunnel helpers:
// explicit UploadPath/DownloadPath halves, upload flush policy, error-wrapping net.Conn,
// and shared client+server relay (h2o-style io.CopyBuffer).
package stream
