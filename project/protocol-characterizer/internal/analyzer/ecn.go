package analyzer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ECNStats struct {
	NotECT int
	ECT0   int
	ECT1   int
	CE     int
	ECE    int
	CWR    int
}

func AnalyzeECN(packet gopacket.Packet, stats *ECNStats) {
	// IPv4 ECN bits are stored in the lower 2 bits of TOS.
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)

		ecn := ipv4.TOS & 0x03

		switch ecn {
		case 0:
			stats.NotECT++
		case 1:
			stats.ECT1++
		case 2:
			stats.ECT0++
		case 3:
			stats.CE++
		}
	}

	// IPv6 ECN bits are part of the Traffic Class field.
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)

		ecn := ipv6.TrafficClass & 0x03

		switch ecn {
		case 0:
			stats.NotECT++
		case 1:
			stats.ECT1++
		case 2:
			stats.ECT0++
		case 3:
			stats.CE++
		}
	}

	// TCP ECN signalling flags.
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)

		if tcp.ECE {
			stats.ECE++
		}

		if tcp.CWR {
			stats.CWR++
		}
	}
}
