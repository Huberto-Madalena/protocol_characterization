package analyzer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCPFlags struct {
	SYN int
	ACK int
	FIN int
	RST int
	PSH int
	URG int
	ECE int
	CWR int
}

func AnalyzeTCPFlags(packet gopacket.Packet, flags *TCPFlags) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp := tcpLayer.(*layers.TCP)

	if tcp.SYN {
		flags.SYN++
	}
	if tcp.ACK {
		flags.ACK++
	}
	if tcp.FIN {
		flags.FIN++
	}
	if tcp.RST {
		flags.RST++
	}
	if tcp.PSH {
		flags.PSH++
	}
	if tcp.URG {
		flags.URG++
	}
	if tcp.ECE {
		flags.ECE++
	}
	if tcp.CWR {
		flags.CWR++
	}
}
