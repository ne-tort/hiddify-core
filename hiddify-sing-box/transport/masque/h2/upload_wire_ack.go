package h2

import "time"

// ConnectUploadWireAck tracks HTTP/2 TLS bytes flushed for Extended CONNECT upload bodies.
type ConnectUploadWireAck interface {
	UploadWireSent() int64
	AwaitUploadWireSent(atLeast int64, timeout time.Duration) error
}
