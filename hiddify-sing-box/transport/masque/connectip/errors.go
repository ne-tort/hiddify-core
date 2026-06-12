package connectip

import "errors"

// Errors are joined into returned errors from Netstack operations. The masque package
// replaces these with its typed sentinels during init.
type Errors struct {
	StackInit      error
	Dial           error
	Closed         error
	DialRequiresIP error
	Transport      error
	Capability     error
}

var defaultErrors = Errors{
	StackInit:      errors.New("connectip: tcp stack init failed"),
	Dial:           errors.New("connectip: tcp dial failed"),
	Closed:         errors.New("connectip: closed"),
	DialRequiresIP: errors.New("connectip: tcp dial requires IP destination"),
	Transport:      errors.New("connectip: transport failed"),
	Capability:     errors.New("connectip: capability error"),
}

// Errs holds sentinel errors used when wrapping operational failures.
var Errs = defaultErrors

// SetErrors installs package-level error sentinels (called from transport/masque init).
func SetErrors(e Errors) {
	if e.StackInit != nil {
		Errs.StackInit = e.StackInit
	}
	if e.Dial != nil {
		Errs.Dial = e.Dial
	}
	if e.Closed != nil {
		Errs.Closed = e.Closed
	}
	if e.DialRequiresIP != nil {
		Errs.DialRequiresIP = e.DialRequiresIP
	}
	if e.Transport != nil {
		Errs.Transport = e.Transport
	}
	if e.Capability != nil {
		Errs.Capability = e.Capability
	}
}
