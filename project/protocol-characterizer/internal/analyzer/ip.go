package analyzer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type IPStats struct {
	IPv4Packets int
	IPv6Packets int

	IPv4Fragmented int
	IPv6Fragmented int

	IPv4WithOptions int

	IPv4TTLTotal int64
	IPv4TTLMin   uint8
	IPv4TTLMax   uint8

	IPv6HopLimitTotal int64
	IPv6HopLimitMin   uint8
	IPv6HopLimitMax   uint8

	IPv4TTLCount      int
	IPv6HopLimitCount int
}

// AnalyzeIP extracts IPv4 and IPv6 header characteristics.
func AnalyzeIP(packet gopacket.Packet, stats *IPStats) {
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)

		stats.IPv4Packets++

		// TTL statistics.
		if stats.IPv4TTLCount == 0 {
			stats.IPv4TTLMin = ipv4.TTL
			stats.IPv4TTLMax = ipv4.TTL
		} else {
			if ipv4.TTL < stats.IPv4TTLMin {
				stats.IPv4TTLMin = ipv4.TTL
			}

			if ipv4.TTL > stats.IPv4TTLMax {
				stats.IPv4TTLMax = ipv4.TTL
			}
		}

		stats.IPv4TTLTotal += int64(ipv4.TTL)
		stats.IPv4TTLCount++

		// IPv4 fragmentation.
		if ipv4.FragOffset != 0 ||
			ipv4.Flags&layers.IPv4MoreFragments != 0 {
			stats.IPv4Fragmented++
		}

		// IPv4 options.
		if len(ipv4.Options) > 0 {
			stats.IPv4WithOptions++
		}

		return
	}

	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)

		stats.IPv6Packets++

		// Hop Limit statistics.
		if stats.IPv6HopLimitCount == 0 {
			stats.IPv6HopLimitMin = ipv6.HopLimit
			stats.IPv6HopLimitMax = ipv6.HopLimit
		} else {
			if ipv6.HopLimit < stats.IPv6HopLimitMin {
				stats.IPv6HopLimitMin = ipv6.HopLimit
			}

			if ipv6.HopLimit > stats.IPv6HopLimitMax {
				stats.IPv6HopLimitMax = ipv6.HopLimit
			}
		}

		stats.IPv6HopLimitTotal += int64(ipv6.HopLimit)
		stats.IPv6HopLimitCount++

		// IPv6 fragmentation is represented through the
		// IPv6 Fragment extension header.
		if packet.Layer(layers.LayerTypeIPv6Fragment) != nil {
			stats.IPv6Fragmented++
		}
	}
}

func (s *IPStats) AverageIPv4TTL() float64 {
	if s.IPv4TTLCount == 0 {
		return 0
	}

	return float64(s.IPv4TTLTotal) / float64(s.IPv4TTLCount)
}

func (s *IPStats) AverageIPv6HopLimit() float64 {
	if s.IPv6HopLimitCount == 0 {
		return 0
	}

	return float64(s.IPv6HopLimitTotal) /
		float64(s.IPv6HopLimitCount)
}
