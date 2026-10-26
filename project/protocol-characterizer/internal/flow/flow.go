package flow

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Key struct {
	SourceIP        string
	DestinationIP   string
	SourcePort      uint16
	DestinationPort uint16
	Protocol        string
}

type Record struct {
	Key Key

	PacketCount int
	ByteCount   int64

	StartTime time.Time
	EndTime   time.Time

	MinPacketSize int
	MaxPacketSize int
	TotalSize     int64

	InterArrivalCount int
	InterArrivalTotal time.Duration
	MinInterArrival   time.Duration
	MaxInterArrival   time.Duration

	LastPacketTime time.Time
}

// AddPacket updates all flow-level statistics for a packet.
func (r *Record) AddPacket(timestamp time.Time, packetSize int) {
	// First packet in the flow.
	if r.PacketCount == 0 {
		r.StartTime = timestamp
		r.EndTime = timestamp
		r.LastPacketTime = timestamp

		r.MinPacketSize = packetSize
		r.MaxPacketSize = packetSize

		r.PacketCount = 1
		r.ByteCount = int64(packetSize)
		r.TotalSize = int64(packetSize)

		return
	}

	// Inter-arrival time.
	interArrival := timestamp.Sub(r.LastPacketTime)

	if interArrival >= 0 {
		if r.InterArrivalCount == 0 {
			r.MinInterArrival = interArrival
			r.MaxInterArrival = interArrival
		} else {
			if interArrival < r.MinInterArrival {
				r.MinInterArrival = interArrival
			}

			if interArrival > r.MaxInterArrival {
				r.MaxInterArrival = interArrival
			}
		}

		r.InterArrivalTotal += interArrival
		r.InterArrivalCount++
	}

	// Keep the most recent packet timestamp.
	if timestamp.After(r.EndTime) {
		r.EndTime = timestamp
	}

	if timestamp.After(r.LastPacketTime) {
		r.LastPacketTime = timestamp
	}

	r.PacketCount++
	r.ByteCount += int64(packetSize)
	r.TotalSize += int64(packetSize)

	if packetSize < r.MinPacketSize {
		r.MinPacketSize = packetSize
	}

	if packetSize > r.MaxPacketSize {
		r.MaxPacketSize = packetSize
	}
}

// Duration returns the elapsed time between the first and last packet.
func (r *Record) Duration() time.Duration {
	if r.PacketCount <= 1 {
		return 0
	}

	return r.EndTime.Sub(r.StartTime)
}

// AveragePacketSize returns the mean captured packet size.
func (r *Record) AveragePacketSize() float64 {
	if r.PacketCount == 0 {
		return 0
	}

	return float64(r.TotalSize) / float64(r.PacketCount)
}

// AverageInterArrival returns the mean inter-arrival time.
func (r *Record) AverageInterArrival() time.Duration {
	if r.InterArrivalCount == 0 {
		return 0
	}

	return time.Duration(
		int64(r.InterArrivalTotal) / int64(r.InterArrivalCount),
	)
}

// PacketsPerSecond returns the flow packet rate.
func (r *Record) PacketsPerSecond() float64 {
	duration := r.Duration().Seconds()

	if duration <= 0 {
		return 0
	}

	return float64(r.PacketCount) / duration
}

// BytesPerSecond returns the flow byte rate.
func (r *Record) BytesPerSecond() float64 {
	duration := r.Duration().Seconds()

	if duration <= 0 {
		return 0
	}

	return float64(r.ByteCount) / duration
}

// GetKey extracts a TCP or UDP 5-tuple from a packet.
func GetKey(packet gopacket.Packet) (Key, bool) {
	var key Key

	var srcIP, dstIP net.IP

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)

		srcIP = ipv4.SrcIP
		dstIP = ipv4.DstIP

	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)

		srcIP = ipv6.SrcIP
		dstIP = ipv6.DstIP

	} else {
		return key, false
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)

		key = Key{
			SourceIP:        srcIP.String(),
			DestinationIP:   dstIP.String(),
			SourcePort:      uint16(tcp.SrcPort),
			DestinationPort: uint16(tcp.DstPort),
			Protocol:        "TCP",
		}

		return key, true
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)

		key = Key{
			SourceIP:        srcIP.String(),
			DestinationIP:   dstIP.String(),
			SourcePort:      uint16(udp.SrcPort),
			DestinationPort: uint16(udp.DstPort),
			Protocol:        "UDP",
		}

		return key, true
	}

	return key, false
}
