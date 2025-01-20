// Package iptrie provides an IP/network tree (trie) implementation for fast IP address lookups.
package iptrie

import (
	"fmt"
	"math/bits"
	"net/netip"
	"strings"
)

// Trie represents operations of a trie.
type Trie[T any] interface {
	fmt.Stringer

	Insert(network netip.Prefix, value T) Trie[T]
	Remove(network netip.Prefix) (T, bool)
	Find(ip netip.Addr) (T, bool)
	FindLargest(ip netip.Addr) (T, bool)
	Contains(ip netip.Addr) bool
	ContainingNetworks(ip netip.Addr) []netip.Prefix
	CoveredNetworks(network netip.Prefix) []netip.Prefix
	GetParent() Trie[T]
	GetNetwork() netip.Prefix
}

// trie is the default implementation of Trie. It is a compressed
// IP radix trie implementation, similar to what is described at
// https://vincent.bernat.im/en/blog/2017-ipv4-route-lookup-linux
//
// Path compression merges nodes with only one child into their parent,
// decreasing the amount of traversals needed when looking up a value.
type trie[T any] struct {
	parent   *trie[T]
	children [2]*trie[T]

	network netip.Prefix
	value   *T
}

// NewTrie creates a new Trie.
func NewTrie[T any]() Trie[T] {
	return newSubTree[T](netip.PrefixFrom(netip.IPv6Unspecified(), 0), nil)
}

func newSubTree[T any](network netip.Prefix, value *T) *trie[T] {
	return &trie[T]{
		network: network,
		value:   value,
	}
}

// Insert inserts an entry into the trie.
func (pt *trie[T]) Insert(network netip.Prefix, value T) Trie[T] {
	network = normalizePrefix(network)
	return pt.insert(network, &value)
}

// Remove removes the entry identified by given network from trie.
func (pt *trie[T]) Remove(network netip.Prefix) (T, bool) {
	network = normalizePrefix(network)
	return pt.remove(network)
}

// Find returns the value from the most specific network (largest prefix) containing the given address.
func (pt *trie[T]) Find(ip netip.Addr) (T, bool) {
	ip = normalizeAddr(ip)
	return pt.find(ip)
}

// FindLargest returns the value from the largest network (smallest prefix) containing the given address.
func (pt *trie[T]) FindLargest(ip netip.Addr) (T, bool) {
	ip = normalizeAddr(ip)
	return pt.findLargest(ip)
}

// Contains indicates whether the trie contains the given ip.
func (pt *trie[T]) Contains(ip netip.Addr) bool {
	ip = normalizeAddr(ip)
	_, contained := pt.findLargest(ip)
	return contained
}

// ContainingNetworks returns the list of networks containing the given ip in ascending prefix order (largest network to
// smallest).
//
// Note: Inserted addresses are normalized to IPv6, so the returned list will be IPv6 only.
func (pt *trie[T]) ContainingNetworks(ip netip.Addr) []netip.Prefix {
	ip = normalizeAddr(ip)
	return pt.containingNetworks(ip)
}

// CoveredNetworks returns the list of networks contained within the given network.
//
// Note: Inserted addresses are normalized to IPv6, so the returned list will be IPv6 only.
func (pt *trie[T]) CoveredNetworks(network netip.Prefix) []netip.Prefix {
	network = normalizePrefix(network)
	return pt.coveredNetworks(network)
}

// GetParent returns the trie's parent (if any).
func (pt *trie[T]) GetParent() Trie[T] {
	return pt.parent
}

// GetNetwork returns the trie's network (if any).
func (pt *trie[T]) GetNetwork() netip.Prefix {
	return pt.network
}

// String returns string representation of trie.
//
// The result will contain implicit nodes which exist as parents for multiple entries, but can be distinguished by the
// lack of a value.
//
// Note: Addresses are normalized to IPv6.
func (pt *trie[T]) String() string {
	children := []string{}
	padding := strings.Repeat("├ ", pt.level()+1)
	for _, child := range pt.children {
		if child == nil {
			continue
		}
		childStr := fmt.Sprintf("\n%s%s", padding, child.String())
		children = append(children, childStr)
	}

	var value string
	if pt.value != nil {
		value = fmt.Sprintf("%v", *pt.value)
		if len(value) > 32 {
			value = value[0:31] + "…"
		}
		value = " • " + value
	}

	return fmt.Sprintf("%s%s%s", pt.network,
		value, strings.Join(children, ""))
}

func (pt *trie[T]) find(ip netip.Addr) (T, bool) {
	if !netContains(pt.network, ip) {
		return zeroValueOfT[T](), false
	}

	if pt.network.Bits() == 128 {
		return *pt.value, true
	}

	bit := pt.discriminatorBitFromIP(ip)
	child := pt.children[bit]
	if child != nil {
		if v, found := child.find(ip); found {
			return v, found
		}
	}

	if pt.value != nil {
		return *pt.value, true
	}
	return zeroValueOfT[T](), false
}

func (pt *trie[T]) findLargest(ip netip.Addr) (T, bool) {
	if !netContains(pt.network, ip) {
		return zeroValueOfT[T](), false
	}

	if pt.value != nil {
		return *pt.value, true
	}

	if pt.network.Bits() == 128 {
		return zeroValueOfT[T](), false
	}

	bit := pt.discriminatorBitFromIP(ip)
	child := pt.children[bit]
	if child != nil {
		return child.findLargest(ip)
	}

	return zeroValueOfT[T](), false
}

func (pt *trie[T]) containingNetworks(ip netip.Addr) []netip.Prefix {
	var results []netip.Prefix
	if !pt.network.Contains(ip) {
		return results
	}
	if pt.value != nil {
		results = []netip.Prefix{pt.network}
	}
	if pt.network.Bits() == 128 {
		return results
	}
	bit := pt.discriminatorBitFromIP(ip)
	child := pt.children[bit]
	if child != nil {
		ranges := child.containingNetworks(ip)
		if len(ranges) > 0 {
			if len(results) > 0 {
				results = append(results, ranges...)
			} else {
				results = ranges
			}
		}
	}
	return results
}

func (pt *trie[T]) coveredNetworks(network netip.Prefix) []netip.Prefix {
	var results []netip.Prefix
	if network.Bits() <= pt.network.Bits() && network.Contains(pt.network.Addr()) {
		for entry := range pt.walkDepth() {
			results = append(results, entry)
		}
	} else if pt.network.Bits() < 128 {
		bit := pt.discriminatorBitFromIP(network.Addr())
		child := pt.children[bit]
		if child != nil {
			return child.coveredNetworks(network)
		}
	}
	return results
}

// This is an unsafe, but faster version of netip.Prefix.Contains
func netContains(pfx netip.Prefix, ip netip.Addr) bool {
	pfxAddr := addr128(pfx.Addr())
	ipAddr := addr128(ip)
	return ipAddr.xor(pfxAddr).and(mask6(pfx.Bits())).isZero()
}

// netDivergence returns the largest prefix shared by the provided 2 prefixes
func netDivergence(net1 netip.Prefix, net2 netip.Prefix) netip.Prefix {
	if net1.Bits() > net2.Bits() {
		net1, net2 = net2, net1
	}

	if netContains(net1, net2.Addr()) {
		return net1
	}

	diff := addr128(net1.Addr()).xor(addr128(net2.Addr()))
	var bit int
	if diff.hi != 0 {
		bit = bits.LeadingZeros64(diff.hi)
	} else {
		bit = bits.LeadingZeros64(diff.lo) + 64
	}
	if bit > net1.Bits() {
		bit = net1.Bits()
	}
	pfx, _ := net1.Addr().Prefix(bit)
	return pfx
}

func (pt *trie[T]) insert(network netip.Prefix, value *T) *trie[T] {
	if pt.network == network {
		pt.value = value
		return pt
	}

	bit := pt.discriminatorBitFromIP(network.Addr())
	existingChild := pt.children[bit]

	// No existing child, insert new leaf trie.
	if existingChild == nil {
		pNew := newSubTree(network, value)
		pt.appendTrie(bit, pNew)
		return pNew
	}

	// Check whether it is necessary to insert additional path prefix between current trie and existing child,
	// in the case that inserted network diverges on its path to existing child.
	netdiv := netDivergence(existingChild.network, network)
	if netdiv != existingChild.network {
		pathPrefix := newSubTree[T](netdiv, nil)
		pt.insertPrefix(bit, pathPrefix, existingChild)
		// Update new child
		existingChild = pathPrefix
	}
	return existingChild.insert(network, value)
}

func (pt *trie[T]) appendTrie(bit uint8, prefix *trie[T]) {
	pt.children[bit] = prefix
	prefix.parent = pt
}

func (pt *trie[T]) insertPrefix(bit uint8, pathPrefix, child *trie[T]) {
	// Set parent/child relationship between current trie and inserted pathPrefix
	pt.children[bit] = pathPrefix
	pathPrefix.parent = pt

	// Set parent/child relationship between inserted pathPrefix and original child
	pathPrefixBit := pathPrefix.discriminatorBitFromIP(child.network.Addr())
	pathPrefix.children[pathPrefixBit] = child
	child.parent = pathPrefix
}

func (pt *trie[T]) remove(network netip.Prefix) (T, bool) {
	if pt.value != nil && pt.network == network {
		entry := *pt.value
		pt.value = nil

		pt.compressPathIfPossible()
		return entry, true
	}
	if pt.network.Bits() == 128 {
		return zeroValueOfT[T](), false
	}
	bit := pt.discriminatorBitFromIP(network.Addr())
	child := pt.children[bit]
	if child != nil {
		return child.remove(network)
	}
	return zeroValueOfT[T](), false
}

func (pt *trie[T]) qualifiesForPathCompression() bool {
	// Current prefix trie can be path compressed if it meets all following.
	//		1. records no CIDR entry
	//		2. has single or no child
	//		3. is not root trie
	return pt.value == nil && pt.childrenCount() <= 1 && pt.parent != nil
}

func (pt *trie[T]) compressPathIfPossible() {
	if !pt.qualifiesForPathCompression() {
		// Does not qualify to be compressed
		return
	}

	// Find lone child.
	var loneChild *trie[T]
	for _, child := range pt.children {
		if child != nil {
			loneChild = child
			break
		}
	}

	// Find root of currnt single child lineage.
	parent := pt.parent
	for ; parent.qualifiesForPathCompression(); parent = parent.parent {
	}
	parentBit := parent.discriminatorBitFromIP(pt.network.Addr())
	parent.children[parentBit] = loneChild

	// Attempts to furthur apply path compression at current lineage parent, in case current lineage
	// compressed into parent.
	parent.compressPathIfPossible()
}

func (pt *trie[T]) childrenCount() int {
	count := 0
	for _, child := range pt.children {
		if child != nil {
			count++
		}
	}
	return count
}

func (pt *trie[T]) discriminatorBitFromIP(addr netip.Addr) uint8 {
	// This is a safe uint boxing of int since we should never attempt to get
	// target bit at a negative position.
	pos := pt.network.Bits()
	a128 := addr128(addr)
	if pos < 64 {
		return uint8(a128.hi >> (63 - pos) & 1)
	}
	return uint8(a128.lo >> (63 - (pos - 64)) & 1)
}

func (pt *trie[T]) level() int {
	if pt.parent == nil {
		return 0
	}
	return pt.parent.level() + 1
}

// walkDepth walks the trie in depth order
func (pt *trie[T]) walkDepth() <-chan netip.Prefix {
	entries := make(chan netip.Prefix)
	go func() {
		if pt.value != nil {
			entries <- pt.network
		}
		childEntriesList := []<-chan netip.Prefix{}
		for _, trie := range pt.children {
			if trie == nil {
				continue
			}
			childEntriesList = append(childEntriesList, trie.walkDepth())
		}
		for _, childEntries := range childEntriesList {
			for entry := range childEntries {
				entries <- entry
			}
		}
		close(entries)
	}()
	return entries
}
