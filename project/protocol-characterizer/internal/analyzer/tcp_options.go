package analyzer

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCPOptions struct {
	SACKPermitted int
	SACKBlocks    int
	WindowScale   int
	MSS           int
	Timestamps    int
}

func AnalyzeTCPOptions(packet gopacket.Packet, options *TCPOptions) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp := tcpLayer.(*layers.TCP)

	for _, option := range tcp.Options {
		switch option.OptionType {
		case layers.TCPOptionKindSACKPermitted:
			options.SACKPermitted++

		case layers.TCPOptionKindSACK:
			options.SACKBlocks++

		case layers.TCPOptionKindWindowScale:
			options.WindowScale++

		case layers.TCPOptionKindMSS:
			options.MSS++

		case layers.TCPOptionKindTimestamps:
			options.Timestamps++
		}
	}
}
