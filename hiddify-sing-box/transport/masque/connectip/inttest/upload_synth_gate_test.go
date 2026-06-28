package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
)

func TestGATEConnectIPUploadSynthNative(t *testing.T) {
	inttest.RunGATEConnectIPUploadSynthNative(t)
}

func TestLocalizeConnectIPUploadNativeObs(t *testing.T) {
	inttest.RunLocalizeConnectIPUploadNativeObs(t)
}

func TestLocalizeConnectIPUploadDatagramWakeCoalescing(t *testing.T) {
	inttest.RunLocalizeConnectIPUploadDatagramWakeCoalescing(t)
}
