package iptrie

import (
	"math/bits"
	"net/netip"
)

// TrieLoader inserts items into a Trie.
type TrieLoader[T any] interface {
	Insert(pfx netip.Prefix, v T)
}

// trieLoader is the default implementation of TrieLoader.
// It can be used to improve the performance of bulk inserts to a Trie.
// It caches the node of the last insert in the tree, using it as the
// starting point to start searching for the location of the next insert.
// This is highly beneficial when the addresses are pre-sorted.
type trieLoader[T any] struct {
	trie       Trie[T]
	lastInsert Trie[T]
}

// NewTrieLoader creates a new TrieLoader.
func NewTrieLoader[T any](trie Trie[T]) TrieLoader[T] {
	return &trieLoader[T]{
		trie:       trie,
		lastInsert: trie,
	}
}

// Insert inserts the value v onto the trie at the given network.
func (ptl *trieLoader[T]) Insert(pfx netip.Prefix, v T) {
	pfx = normalizePrefix(pfx)

	lastInsertNetwork := ptl.lastInsert.GetNetwork()
	diff := addr128(lastInsertNetwork.Addr()).xor(addr128(pfx.Addr()))
	var pos int
	if diff.hi != 0 {
		pos = bits.LeadingZeros64(diff.hi)
	} else {
		pos = bits.LeadingZeros64(diff.lo) + 64
	}
	if pos > pfx.Bits() {
		pos = pfx.Bits()
	}
	if pos > lastInsertNetwork.Bits() {
		pos = lastInsertNetwork.Bits()
	}

	parent := ptl.lastInsert
	for parent.GetNetwork().Bits() > pos {
		parent = parent.GetParent()
	}
	ptl.lastInsert = parent.Insert(pfx, v)
}
