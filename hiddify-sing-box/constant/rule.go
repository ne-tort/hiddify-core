package constant

const (
	RuleTypeDefault = "default"
	RuleTypeLogical = "logical"
)

const (
	LogicalTypeAnd = "and"
	LogicalTypeOr  = "or"
)

const (
	RuleSetTypeInline   = "inline"
	RuleSetTypeLocal    = "local"
	RuleSetTypeRemote   = "remote"
	RuleSetFormatSource = "source"
	RuleSetFormatBinary = "binary"
)

const (
	RuleSetVersion1 = 1 + iota
	RuleSetVersion2
	RuleSetVersion3
	RuleSetVersion4
	RuleSetVersionCurrent = RuleSetVersion4
)

const (
	RuleActionTypeRoute        = "route"
	RuleActionTypeRouteOptions = "route-options"
	RuleActionTypeDirect       = "direct"
	RuleActionTypeBypass       = "bypass"
	RuleActionTypeReject       = "reject"
	RuleActionTypeHijackDNS    = "hijack-dns"
	RuleActionTypeSniff        = "sniff"
	RuleActionTypeResolve      = "resolve"
	RuleActionTypePredefined   = "predefined"
)

const (
	RuleActionRejectMethodDefault = "default"
	RuleActionRejectMethodDrop    = "drop"
	RuleActionRejectMethodReply   = "reply"
)

// RouteConnectionCopyWriterTo marks a TCP relay source where route.ConnectionManager may use
// io.WriterTo instead of bufio.CopyWithCounters. Implemented by MASQUE CONNECT-stream streamConn
// so download pulls large reads from the HTTP/2/3 body; other conns must not implement this marker.
type RouteConnectionCopyWriterTo interface {
	RouteConnectionCopyWriterTo()
}

// RouteConnectionCopyReaderFrom marks a TCP relay sink where route.ConnectionManager may use
// io.ReaderFrom instead of bufio.CopyWithCounters. Implemented by MASQUE CONNECT-stream streamConn
// for bulk upload from the TUN side; other conns must not implement this marker.
type RouteConnectionCopyReaderFrom interface {
	RouteConnectionCopyReaderFrom()
}
