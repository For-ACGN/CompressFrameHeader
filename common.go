package cfh

import (
	"encoding/binary"
)

const (
	// MaxFrameHeaderSize is the maximum frame header.
	MaxFrameHeaderSize = 256

	// MaxDictionarySize is the maximum dictionary size.
	MaxDictionarySize = 256
)

const (
	cmdAddDict = 1 + iota
	cmdData
	cmdLast
	cmdPrev
)

const (
	ethernetIPv4TCPSize = 14 + 20 + 20
	ethernetIPv4UDPSize = 14 + 20 + 8
	ethernetIPv6TCPSize = 14 + 40 + 20
	ethernetIPv6UDPSize = 14 + 40 + 8
)

// for select dictionary faster in slowSearchDict.
const (
	minDiffDiv = 10
	maxDiffDiv = 4
)

// IsFrameHeaderPreferBeCompressed is used to check
// frame header can be compressed by fast mode.
// If frame header is preferred be compressed, it will
// return the header size that be compressed.
// It supports IPv4/IPv6 with TCP/UDP
func IsFrameHeaderPreferBeCompressed(frame []byte) (int, bool) {
	if len(frame) < ethernetIPv4UDPSize {
		return 0, false
	}
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case 0x0800: // IPv4
		// check version is 4 and header length is 20
		if frame[14] != 0x45 {
			return 0, false
		}
		switch frame[23] {
		case 0x06: // TCP
			if len(frame) < ethernetIPv4TCPSize {
				return 0, false
			}
			// check header length is 20
			if frame[46]>>4 != 0x05 {
				return 0, false
			}
			return ethernetIPv4TCPSize, true
		case 0x11: // UDP
			// fixed header length
			return ethernetIPv4UDPSize, true
		default:
			return 0, false
		}
	case 0x86DD: // IPv6
		// fixed header length
		switch frame[20] {
		case 0x06: // TCP
			if len(frame) < ethernetIPv6TCPSize {
				return 0, false
			}
			// check header length is 20
			if frame[66]>>4 != 0x05 {
				return 0, false
			}
			return ethernetIPv6TCPSize, true
		case 0x11: // UDP
			if len(frame) < ethernetIPv6UDPSize {
				return 0, false
			}
			// fixed header length
			return ethernetIPv6UDPSize, true
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}
