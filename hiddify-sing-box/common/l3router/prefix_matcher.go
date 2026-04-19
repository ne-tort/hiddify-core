// Prefix membership for packet filter (filter source / destination). Not the egress FIB; LPM uses allowedIPTable.
package l3router

import (
	"encoding/binary"
	"net/netip"
)

type prefixMatcher struct {
	allowAll bool
	v4       *prefixTrieNodeV4
	v6       *prefixTrieNodeV6
}

type prefixTrieNodeV4 struct {
	child [2]*prefixTrieNodeV4
	match bool
}

type prefixTrieNodeV6 struct {
	child [2]*prefixTrieNodeV6
	match bool
}

func newPrefixMatcher(list []netip.Prefix) prefixMatcher {
	if len(list) == 0 {
		return prefixMatcher{allowAll: true}
	}
	m := prefixMatcher{}
	for _, p := range list {
		if p.Addr().Is4() {
			ip := p.Addr().As4()
			m.v4 = prefixInsertV4(m.v4, binary.BigEndian.Uint32(ip[:]), p.Bits())
		} else if p.Addr().Is6() {
			ip := p.Addr().As16()
			m.v6 = prefixInsertV6(m.v6, ip[:], p.Bits())
		}
	}
	return m
}

func (m prefixMatcher) hasRules() bool {
	return !m.allowAll
}

func (m prefixMatcher) contains(addr netip.Addr) bool {
	if m.allowAll {
		return true
	}
	if addr.Is4() {
		ip := addr.As4()
		return prefixContainsV4(m.v4, binary.BigEndian.Uint32(ip[:]))
	}
	if addr.Is6() {
		ip := addr.As16()
		return prefixContainsV6Bytes(m.v6, ip[:])
	}
	return false
}

func (m prefixMatcher) containsV4(v uint32) bool {
	if m.allowAll {
		return true
	}
	return prefixContainsV4(m.v4, v)
}

func (m prefixMatcher) containsV6(hi, lo uint64) bool {
	if m.allowAll {
		return true
	}
	return prefixContainsV6HiLo(m.v6, hi, lo)
}

func prefixInsertV4(root *prefixTrieNodeV4, addr uint32, bits int) *prefixTrieNodeV4 {
	if root == nil {
		root = &prefixTrieNodeV4{}
	}
	n := root
	for i := 0; i < bits; i++ {
		b := int((addr >> uint(31-i)) & 1)
		if n.child[b] == nil {
			n.child[b] = &prefixTrieNodeV4{}
		}
		n = n.child[b]
	}
	n.match = true
	return root
}

func prefixInsertV6(root *prefixTrieNodeV6, addr []byte, bits int) *prefixTrieNodeV6 {
	if root == nil {
		root = &prefixTrieNodeV6{}
	}
	n := root
	for i := 0; i < bits; i++ {
		b := int((addr[i/8] >> (7 - uint(i%8))) & 1)
		if n.child[b] == nil {
			n.child[b] = &prefixTrieNodeV6{}
		}
		n = n.child[b]
	}
	n.match = true
	return root
}

func prefixContainsV4(root *prefixTrieNodeV4, addr uint32) bool {
	if root == nil {
		return false
	}
	n := root
	if n.match {
		return true
	}
	for i := 0; i < 32; i++ {
		b := int((addr >> uint(31-i)) & 1)
		n = n.child[b]
		if n == nil {
			return false
		}
		if n.match {
			return true
		}
	}
	return false
}

func prefixContainsV6HiLo(root *prefixTrieNodeV6, hi, lo uint64) bool {
	if root == nil {
		return false
	}
	n := root
	if n.match {
		return true
	}
	for i := 0; i < 64; i++ {
		b := int((hi >> uint(63-i)) & 1)
		n = n.child[b]
		if n == nil {
			return false
		}
		if n.match {
			return true
		}
	}
	for i := 0; i < 64; i++ {
		b := int((lo >> uint(63-i)) & 1)
		n = n.child[b]
		if n == nil {
			return false
		}
		if n.match {
			return true
		}
	}
	return false
}

func prefixContainsV6Bytes(root *prefixTrieNodeV6, addr []byte) bool {
	if root == nil {
		return false
	}
	n := root
	if n.match {
		return true
	}
	for i := 0; i < len(addr)*8; i++ {
		b := int((addr[i/8] >> (7 - uint(i%8))) & 1)
		n = n.child[b]
		if n == nil {
			return false
		}
		if n.match {
			return true
		}
	}
	return false
}
