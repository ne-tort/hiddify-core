package connectip

import (
	"crypto/tls"
	"testing"
)

func TestDialAuthFromInputOmitsWhenEmpty(t *testing.T) {
	auth := DialAuthFromInput(DialAuthInput{})
	if auth.BearerToken != "" || auth.ExtraRequestHeaders != nil {
		t.Fatalf("expected empty auth, got %+v", auth)
	}
}

func TestDialAuthFromInputServerToken(t *testing.T) {
	auth := DialAuthFromInput(DialAuthInput{ServerToken: "tok"})
	if auth.BearerToken != "tok" {
		t.Fatalf("got %q", auth.BearerToken)
	}
}

func TestDialAuthFromInputBasicWins(t *testing.T) {
	auth := DialAuthFromInput(DialAuthInput{
		ServerToken:                 "tok",
		ClientBasicUsername:         "u",
		ClientBasicPassword:         "p",
		WarpMasqueDeviceBearerToken: "device",
	})
	if auth.BearerToken != "" {
		t.Fatalf("basic must clear bearer, got %q", auth.BearerToken)
	}
	if got := auth.ExtraRequestHeaders.Get("Authorization"); !stringsHasPrefix(got, "Basic ") {
		t.Fatalf("got %q", got)
	}
}

func TestDialAuthFromInputOmitsDeviceWhenMTLS(t *testing.T) {
	auth := DialAuthFromInput(DialAuthInput{
		WarpMasqueDeviceBearerToken: "device",
		WarpMasqueClientCert: tls.Certificate{
			Certificate: [][]byte{[]byte("der")},
		},
	})
	if auth.BearerToken != "" {
		t.Fatalf("expected omit device bearer with mTLS, got %q", auth.BearerToken)
	}
}

func TestDialAuthFromInputDeviceWhenNoMTLS(t *testing.T) {
	auth := DialAuthFromInput(DialAuthInput{WarpMasqueDeviceBearerToken: "device"})
	if auth.BearerToken != "device" {
		t.Fatalf("got %q", auth.BearerToken)
	}
}

func TestDialAuthFromInputServerTokenWinsOverMTLS(t *testing.T) {
	auth := DialAuthFromInput(DialAuthInput{
		ServerToken: "explicit",
		WarpMasqueDeviceBearerToken: "device",
		WarpMasqueClientCert: tls.Certificate{
			Certificate: [][]byte{[]byte("der")},
		},
	})
	if auth.BearerToken != "explicit" {
		t.Fatalf("got %q", auth.BearerToken)
	}
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
