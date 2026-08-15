package config

import (
	"net"
	"testing"
)

func TestKeepIPv6Leaves(t *testing.T) {
	t.Parallel()
	if KeepIPv6Leaves(true, true) != true {
		t.Fatal("want keep when os+sub")
	}
	if KeepIPv6Leaves(true, false) {
		t.Fatal("drop when sub false")
	}
	if KeepIPv6Leaves(false, true) {
		t.Fatal("drop when os false")
	}
}

func TestHasUsableGlobalIPv6IgnoresLoopbackOnly(t *testing.T) {
	t.Parallel()
	// Smoke: function must return without panic; result is host-dependent.
	_ = hasUsableGlobalIPv6()
}

func TestIsUsableGlobalIPv6Addr(t *testing.T) {
	t.Parallel()
	if isUsableGlobalIPv6Addr(net.ParseIP("2001:db8::1")) != true {
		t.Fatal("global unicast should keep")
	}
	if isUsableGlobalIPv6Addr(net.ParseIP("2001:0:14c9:d804:38b9:2d6b:a118:78e1")) {
		t.Fatal("teredo must drop")
	}
	if isUsableGlobalIPv6Addr(net.ParseIP("2002:c000:0201::1")) {
		t.Fatal("6to4 must drop")
	}
	if isUsableGlobalIPv6Addr(net.ParseIP("fd10:8:a::1")) {
		t.Fatal("ula must drop")
	}
	if isUsableGlobalIPv6Addr(net.ParseIP("fe80::1")) {
		t.Fatal("link-local must drop")
	}
	if isUsableGlobalIPv6Addr(net.ParseIP("::1")) {
		t.Fatal("loopback must drop")
	}
}

func TestIsIPv6Leaf(t *testing.T) {
	t.Parallel()
	if !IsIPv6Leaf("proxy-ipv6", "") {
		t.Fatal("suffix")
	}
	if !IsIPv6Leaf("x", "2001:db8::1") {
		t.Fatal("literal")
	}
	if !IsIPv6Leaf("x", "[2001:db8::1]") {
		t.Fatal("bracket literal")
	}
	if IsIPv6Leaf("proxy-ipv4", "1.2.3.4") {
		t.Fatal("v4 must not match")
	}
}
