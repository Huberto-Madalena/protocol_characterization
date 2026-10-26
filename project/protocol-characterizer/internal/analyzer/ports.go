package analyzer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type PortStats struct {
	SourcePorts      map[uint16]int
	DestinationPorts map[uint16]int
	PortPairs        map[PortPair]int
	ServiceCounts    map[string]int
}

type PortPair struct {
	SourcePort      uint16
	DestinationPort uint16
	Protocol        string
}

// InitPortStats initializes all maps used for port analysis.
func InitPortStats() PortStats {
	return PortStats{
		SourcePorts:      make(map[uint16]int),
		DestinationPorts: make(map[uint16]int),
		PortPairs:        make(map[PortPair]int),
		ServiceCounts:    make(map[string]int),
	}
}

// AnalyzePorts extracts TCP/UDP port usage from a packet.
func AnalyzePorts(packet gopacket.Packet, stats *PortStats) {
	if stats.SourcePorts == nil {
		stats.SourcePorts = make(map[uint16]int)
	}

	if stats.DestinationPorts == nil {
		stats.DestinationPorts = make(map[uint16]int)
	}

	if stats.PortPairs == nil {
		stats.PortPairs = make(map[PortPair]int)
	}

	if stats.ServiceCounts == nil {
		stats.ServiceCounts = make(map[string]int)
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)

		srcPort := uint16(tcp.SrcPort)
		dstPort := uint16(tcp.DstPort)

		stats.SourcePorts[srcPort]++
		stats.DestinationPorts[dstPort]++

		pair := PortPair{
			SourcePort:      srcPort,
			DestinationPort: dstPort,
			Protocol:        "TCP",
		}

		stats.PortPairs[pair]++

		if service := InferService("TCP", srcPort, dstPort); service != "" {
			stats.ServiceCounts[service]++
		}

		return
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)

		srcPort := uint16(udp.SrcPort)
		dstPort := uint16(udp.DstPort)

		stats.SourcePorts[srcPort]++
		stats.DestinationPorts[dstPort]++

		pair := PortPair{
			SourcePort:      srcPort,
			DestinationPort: dstPort,
			Protocol:        "UDP",
		}

		stats.PortPairs[pair]++

		if service := InferService("UDP", srcPort, dstPort); service != "" {
			stats.ServiceCounts[service]++
		}
	}
}

// InferService performs simple port-based service inference.
// This is an inference only and does not prove application identity.
func InferService(protocol string, srcPort, dstPort uint16) string {
	servicePort := dstPort

	// If the source port is a well-known port and the destination
	// appears ephemeral, use the source port for inference.
	if srcPort <= 1023 && dstPort > 1023 {
		servicePort = srcPort
	}

	switch protocol {
	case "TCP":
		switch servicePort {
		case 20:
			return "FTP Data"
		case 21:
			return "FTP Control"
		case 22:
			return "SSH"
		case 23:
			return "Telnet"
		case 25:
			return "SMTP"
		case 53:
			return "DNS"
		case 80:
			return "HTTP"
		case 110:
			return "POP3"
		case 143:
			return "IMAP"
		case 443:
			return "HTTPS"
		case 993:
			return "IMAPS"
		case 995:
			return "POP3S"
		}

	case "UDP":
		switch servicePort {
		case 53:
			return "DNS"
		case 67:
			return "DHCP Server"
		case 68:
			return "DHCP Client"
		case 69:
			return "TFTP"
		case 123:
			return "NTP"
		case 161:
			return "SNMP"
		case 162:
			return "SNMP Trap"
		case 500:
			return "IKE"
		case 514:
			return "Syslog"
		case 5353:
			return "mDNS"
		}
	}

	return ""
}
