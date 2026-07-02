package connectudp

import "errors"

// ErrPrivateTargetDenied is returned when onward ACL blocks loopback/private targets.
var ErrPrivateTargetDenied = errors.New("private target denied")
