package config

import "testing"

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
