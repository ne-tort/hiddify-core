/* SPDX-License-Identifier: MIT
 *
 * Derived from wireguard-go allowedips implementation.
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package l3router

import (
	"encoding/binary"
	"math/bits"
	"net"
	"net/netip"
)

type parentRef struct {
	slot **peerTrieEntry
}

type peerTrieEntry struct {
	peerID     PeerID
	hasPeer    bool
	child      [2]*peerTrieEntry
	parent     parentRef
	cidr       uint8
	bitAtByte  uint8
	bitAtShift uint8
	bits       []byte
}

type allowedIPTable struct {
	ipv4 *peerTrieEntry
	ipv6 *peerTrieEntry
}

func commonBitsPeer(ip1, ip2 []byte) uint8 {
	size := len(ip1)
	if size == net.IPv4len {
		x := binary.BigEndian.Uint32(ip1) ^ binary.BigEndian.Uint32(ip2)
		return uint8(bits.LeadingZeros32(x))
	}
	if size == net.IPv6len {
		x := binary.BigEndian.Uint64(ip1) ^ binary.BigEndian.Uint64(ip2)
		if x != 0 {
			return uint8(bits.LeadingZeros64(x))
		}
		x = binary.BigEndian.Uint64(ip1[8:]) ^ binary.BigEndian.Uint64(ip2[8:])
		return 64 + uint8(bits.LeadingZeros64(x))
	}
	return 0
}

func (node *peerTrieEntry) choose(ip []byte) byte {
	return (ip[node.bitAtByte] >> node.bitAtShift) & 1
}

func (node *peerTrieEntry) maskSelf() {
	mask := net.CIDRMask(int(node.cidr), len(node.bits)*8)
	for i := 0; i < len(mask); i++ {
		node.bits[i] &= mask[i]
	}
}

func (node *peerTrieEntry) nodePlacement(ip []byte, cidr uint8) (parent *peerTrieEntry, exact bool) {
	for node != nil && node.cidr <= cidr && commonBitsPeer(node.bits, ip) >= node.cidr {
		parent = node
		if parent.cidr == cidr {
			return parent, true
		}
		node = node.child[node.choose(ip)]
	}
	return parent, false
}

func (slot parentRef) insert(ip []byte, cidr uint8, peerID PeerID) {
	if *slot.slot == nil {
		node := &peerTrieEntry{
			peerID:     peerID,
			hasPeer:    true,
			parent:     slot,
			bits:       append([]byte(nil), ip...),
			cidr:       cidr,
			bitAtByte:  cidr / 8,
			bitAtShift: 7 - (cidr % 8),
		}
		node.maskSelf()
		*slot.slot = node
		return
	}
	node, exact := (*slot.slot).nodePlacement(ip, cidr)
	if exact {
		node.peerID = peerID
		node.hasPeer = true
		return
	}

	newNode := &peerTrieEntry{
		peerID:     peerID,
		hasPeer:    true,
		bits:       append([]byte(nil), ip...),
		cidr:       cidr,
		bitAtByte:  cidr / 8,
		bitAtShift: 7 - (cidr % 8),
	}
	newNode.maskSelf()

	var down *peerTrieEntry
	if node == nil {
		down = *slot.slot
	} else {
		bit := node.choose(ip)
		down = node.child[bit]
		if down == nil {
			newNode.parent = parentRef{slot: &node.child[bit]}
			node.child[bit] = newNode
			return
		}
	}

	common := commonBitsPeer(down.bits, ip)
	if common < cidr {
		cidr = common
	}
	parent := node
	if newNode.cidr == cidr {
		bit := newNode.choose(down.bits)
		down.parent = parentRef{slot: &newNode.child[bit]}
		newNode.child[bit] = down
		if parent == nil {
			newNode.parent = slot
			*slot.slot = newNode
		} else {
			pbit := parent.choose(newNode.bits)
			newNode.parent = parentRef{slot: &parent.child[pbit]}
			parent.child[pbit] = newNode
		}
		return
	}

	mid := &peerTrieEntry{
		bits:       append([]byte(nil), newNode.bits...),
		cidr:       cidr,
		bitAtByte:  cidr / 8,
		bitAtShift: 7 - (cidr % 8),
	}
	mid.maskSelf()
	bitDown := mid.choose(down.bits)
	down.parent = parentRef{slot: &mid.child[bitDown]}
	mid.child[bitDown] = down
	bitNew := mid.choose(newNode.bits)
	newNode.parent = parentRef{slot: &mid.child[bitNew]}
	mid.child[bitNew] = newNode
	if parent == nil {
		mid.parent = slot
		*slot.slot = mid
	} else {
		pbit := parent.choose(mid.bits)
		mid.parent = parentRef{slot: &parent.child[pbit]}
		parent.child[pbit] = mid
	}
}

func (node *peerTrieEntry) lookup(ip []byte) (PeerID, bool) {
	var found PeerID
	hasFound := false
	size := uint8(len(ip))
	for node != nil && commonBitsPeer(node.bits, ip) >= node.cidr {
		if node.hasPeer {
			found = node.peerID
			hasFound = true
		}
		if node.bitAtByte == size {
			break
		}
		node = node.child[node.choose(ip)]
	}
	return found, hasFound
}

func (t *allowedIPTable) insert(prefix netip.Prefix, peerID PeerID) {
	if prefix.Addr().Is6() {
		ip := prefix.Addr().As16()
		parentRef{slot: &t.ipv6}.insert(ip[:], uint8(prefix.Bits()), peerID)
		return
	}
	if prefix.Addr().Is4() {
		ip := prefix.Addr().As4()
		parentRef{slot: &t.ipv4}.insert(ip[:], uint8(prefix.Bits()), peerID)
	}
}

func (t *allowedIPTable) lookupV4(addr uint32) (PeerID, bool) {
	if t.ipv4 == nil {
		return 0, false
	}
	var ip [4]byte
	binary.BigEndian.PutUint32(ip[:], addr)
	return t.ipv4.lookup(ip[:])
}

func (t *allowedIPTable) lookupV6(hi, lo uint64) (PeerID, bool) {
	if t.ipv6 == nil {
		return 0, false
	}
	var ip [16]byte
	binary.BigEndian.PutUint64(ip[:8], hi)
	binary.BigEndian.PutUint64(ip[8:], lo)
	return t.ipv6.lookup(ip[:])
}
