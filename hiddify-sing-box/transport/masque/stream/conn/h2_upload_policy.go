package conn

// H2ConnectStreamBufLen is the prod bulk I/O unit (256 KiB; parity H3 TunnelWriteToBufLen + x/net bulk flush).
const H2ConnectStreamBufLen = 256 * 1024

// H2ConnectUploadChunkBytes is ReadFrom/bootstrap upload chunk size (must match bulk TLS flush threshold).
const H2ConnectUploadChunkBytes = H2ConnectStreamBufLen

// H2ConnectStreamWriteToBufLen is the prod route WriteTo drain buffer.
const H2ConnectStreamWriteToBufLen = H2ConnectStreamBufLen
