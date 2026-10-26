package decoder

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PacketInfo struct {
	Ethernet *layers.Ethernet
	IPv4     *layers.IPv4
	IPv6     *layers.IPv6
	TCP      *layers.TCP
	UDP      *layers.UDP

	HasEthernet bool
	HasIPv4     bool
	HasIPv6     bool
	HasTCP      bool
	HasUDP      bool
}

// Decode extracts supported protocol layers from a gopacket packet.
//
// The decoder does not perform protocol analysis.
// It only identifies and exposes decoded layers for the rest
// of the framework.
func Decode(packet gopacket.Packet) PacketInfo {
	var info PacketInfo

	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		info.Ethernet = ethernetLayer.(*layers.Ethernet)
		info.HasEthernet = true
	}

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		info.IPv4 = ipv4Layer.(*layers.IPv4)
		info.HasIPv4 = true
	}

	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		info.IPv6 = ipv6Layer.(*layers.IPv6)
		info.HasIPv6 = true
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		info.TCP = tcpLayer.(*layers.TCP)
		info.HasTCP = true
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		info.UDP = udpLayer.(*layers.UDP)
		info.HasUDP = true
	}

	return info
}
