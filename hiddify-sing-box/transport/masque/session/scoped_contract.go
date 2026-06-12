package session

import "errors"

const (
	// ErrorSourceRuntime marks failures originating from fast runtime/go harness paths.
	ErrorSourceRuntime = "runtime"
	// ErrorSourceComposeUp marks failures raised before traffic phase during compose/bootstrap.
	ErrorSourceComposeUp = "compose_up"
)

// ScopedErrorArtifact keeps malformed scoped CONNECT-IP classification deterministic across layers.
type ScopedErrorArtifact struct {
	OK                   bool       `json:"ok"`
	ActualErrorClass     ErrorClass `json:"actual_error_class"`
	ResultErrorClass     ErrorClass `json:"result_error_class"`
	ErrorClassConsistent bool       `json:"error_class_consistent"`
	ErrorSource          string     `json:"error_source"`
}

// BuildScopedErrorArtifact creates a typed artifact payload used by pre-docker runtime/transport gates.
func BuildScopedErrorArtifact(actualClass, resultClass ErrorClass, source string) ScopedErrorArtifact {
	source = NormalizeErrorSource(source)
	ok := actualClass == resultClass && (actualClass == ErrorClassCapability || actualClass == ErrorClassPolicy)
	return ScopedErrorArtifact{
		OK:                   ok,
		ActualErrorClass:     actualClass,
		ResultErrorClass:     resultClass,
		ErrorClassConsistent: ok,
		ErrorSource:          source,
	}
}

// NormalizeErrorSource keeps artifact source values within stable boundary enum.
func NormalizeErrorSource(source string) string {
	switch source {
	case ErrorSourceRuntime, ErrorSourceComposeUp:
		return source
	default:
		return ErrorSourceRuntime
	}
}

// ClassifyMalformedScopedTargetClassPair classifies malformed scoped CONNECT-IP template options.
func ClassifyMalformedScopedTargetClassPair(options ClientOptions, hooks TemplateURIHooks) (actualClass ErrorClass, resultClass ErrorClass, err error) {
	_, _, _, buildErr := BuildTemplates(options, hooks)
	if buildErr == nil {
		return ErrorClassUnknown, ErrorClassUnknown, errors.New("expected malformed connect_ip scope target to fail")
	}
	actualClass = ClassifyError(buildErr)
	resultClass = ClassifyError(errors.Join(ErrCapability, buildErr))
	return actualClass, resultClass, buildErr
}
