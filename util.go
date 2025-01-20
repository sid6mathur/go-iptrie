package iptrie

import (
	"net/netip"
	"unsafe"
)

func zeroValueOfT[T any]() T {
	var t T
	return t
}

func normalizeAddr(addr netip.Addr) netip.Addr {
	if addr.Is4() {
		return netip.AddrFrom16(addr.As16())
	}
	return addr
}

func normalizePrefix(pfx netip.Prefix) netip.Prefix {
	if pfx.Addr().Is4() {
		pfx = netip.PrefixFrom(netip.AddrFrom16(pfx.Addr().As16()), pfx.Bits()+96)
	}
	return pfx.Masked()
}

func addr128(addr netip.Addr) uint128 {
	return *(*uint128)(unsafe.Pointer(&addr))
}

func init() {
	// Accessing the underlying data of a `netip.Addr` relies upon the data being
	// in a known format, which is not guaranteed to be stable. So this init()
	// function is to detect if it ever changes.
	ip := netip.AddrFrom16([16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	i128 := addr128(ip)
	if i128.hi != 0x0001020304050607 || i128.lo != 0x08090a0b0c0d0e0f {
		panic("netip.Addr format mismatch")
	}
}
