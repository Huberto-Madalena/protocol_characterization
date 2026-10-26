package analyzer

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ChecksumResult struct {
	Present      int
	Absent       int
	Valid        int
	Invalid      int
	Unverifiable int
}

type ChecksumStats struct {
	IPv4 ChecksumResult
	TCP  ChecksumResult
	UDP  ChecksumResult
}

func AnalyzeChecksums(packet gopacket.Packet, stats *ChecksumStats) {
	truncated := false

	if metadata := packet.Metadata(); metadata != nil {
		if metadata.CaptureLength < metadata.Length {
			truncated = true
		}
	}

	// IPv4 header checksum
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		stats.IPv4.Present++

		header := ipv4.LayerContents()

		if len(header) < 20 {
			stats.IPv4.Unverifiable++
		} else if checksumValid(header, 0) {
			stats.IPv4.Valid++
		} else {
			stats.IPv4.Invalid++
		}
	}

	// TCP checksum
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		stats.TCP.Present++

		if truncated || packetFragmented(packet) {
			stats.TCP.Unverifiable++
		} else {
			segment := append(
				append([]byte{}, tcp.LayerContents()...),
				tcp.LayerPayload()...,
			)

			if transportChecksumValid(packet, segment, 6) {
				stats.TCP.Valid++
			} else {
				stats.TCP.Invalid++
			}
		}
	}

	// UDP checksum
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)

		// A zero UDP checksum represents no checksum.
		if udp.Checksum == 0 {
			stats.UDP.Absent++
			return
		}

		stats.UDP.Present++

		if truncated || packetFragmented(packet) {
			stats.UDP.Unverifiable++
		} else {
			datagram := append(
				append([]byte{}, udp.LayerContents()...),
				udp.LayerPayload()...,
			)

			if transportChecksumValid(packet, datagram, 17) {
				stats.UDP.Valid++
			} else {
				stats.UDP.Invalid++
			}
		}
	}
}

func packetFragmented(packet gopacket.Packet) bool {
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)

		if ipv4.FragOffset != 0 ||
			ipv4.Flags&layers.IPv4MoreFragments != 0 {
			return true
		}
	}

	if packet.Layer(layers.LayerTypeIPv6Fragment) != nil {
		return true
	}

	return false
}

func transportChecksumValid(
	packet gopacket.Packet,
	data []byte,
	protocol uint8,
) bool {
	var sum uint32

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)

		src := ipv4.SrcIP.To4()
		dst := ipv4.DstIP.To4()

		if src == nil || dst == nil {
			return false
		}

		sum += sumBytes(src)
		sum += sumBytes(dst)
		sum += uint32(protocol)
		sum += uint32(len(data))

	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)

		src := ipv6.SrcIP.To16()
		dst := ipv6.DstIP.To16()

		if src == nil || dst == nil {
			return false
		}

		sum += sumBytes(src)
		sum += sumBytes(dst)

		length := uint32(len(data))
		sum += length >> 16
		sum += length & 0xffff
		sum += uint32(protocol)

	} else {
		return false
	}

	sum += sumBytes(data)

	return foldChecksum(sum) == 0xffff
}

func checksumValid(data []byte, initial uint32) bool {
	sum := initial + sumBytes(data)
	return foldChecksum(sum) == 0xffff
}

func sumBytes(data []byte) uint32 {
	var sum uint32

	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}

	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}

	return sum
}

func foldChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return uint16(sum)
}
