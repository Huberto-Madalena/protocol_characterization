package compliance

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"protocol-characterizer/internal/analyzer"
)

type Status string

const (
	StatusCompliant     Status = "Compliant"
	StatusNonCompliant  Status = "Non-compliant"
	StatusUnverifiable  Status = "Unverifiable"
	StatusNotApplicable Status = "Not applicable"
)

type RuleResult struct {
	Name    string
	Status  Status
	Details string
}

type Stats struct {
	Compliant     int
	NonCompliant  int
	Unverifiable  int
	NotApplicable int

	Results []RuleResult
}

// AnalyzePacket evaluates a small set of defensible protocol-compliance rules.
//
// Important:
// These checks only assess properties observable in the captured packet.
// They do not prove complete RFC compliance for an entire connection or
// application exchange.
func AnalyzePacket(
	packet gopacket.Packet,
	checksums analyzer.ChecksumStats,
	stats *Stats,
) {
	analyzeIPv4Header(packet, checksums, stats)
	analyzeUDPChecksum(packet, checksums, stats)
	analyzeTCPFlags(packet, stats)
}

func addResult(
	stats *Stats,
	name string,
	status Status,
	details string,
) {
	stats.Results = append(
		stats.Results,
		RuleResult{
			Name:    name,
			Status:  status,
			Details: details,
		},
	)

	switch status {
	case StatusCompliant:
		stats.Compliant++
	case StatusNonCompliant:
		stats.NonCompliant++
	case StatusUnverifiable:
		stats.Unverifiable++
	case StatusNotApplicable:
		stats.NotApplicable++
	}
}

func analyzeIPv4Header(
	packet gopacket.Packet,
	checksums analyzer.ChecksumStats,
	stats *Stats,
) {
	if packet.Layer(layers.LayerTypeIPv4) == nil {
		return
	}

	ipv4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

	if ipv4.Version != 4 {
		addResult(
			stats,
			"IPv4 version field",
			StatusNonCompliant,
			"IPv4 packet does not contain version value 4.",
		)
	} else {
		addResult(
			stats,
			"IPv4 version field",
			StatusCompliant,
			"IPv4 version field is 4.",
		)
	}

	if ipv4.IHL < 5 {
		addResult(
			stats,
			"IPv4 header length",
			StatusNonCompliant,
			"IPv4 IHL is smaller than the minimum value of 5.",
		)
	} else {
		addResult(
			stats,
			"IPv4 header length",
			StatusCompliant,
			"IPv4 header length is at least 20 bytes.",
		)
	}

	// Compare checksum counters before/after packet analysis indirectly.
	// For this prototype, the aggregate checksum result is used only when
	// the current capture contains a single IPv4 packet. More precise
	// packet-level checksum status will be introduced later.
	if checksums.IPv4.Invalid > 0 {
		addResult(
			stats,
			"IPv4 header checksum",
			StatusNonCompliant,
			"At least one IPv4 header checksum was invalid.",
		)
	} else if checksums.IPv4.Valid > 0 {
		addResult(
			stats,
			"IPv4 header checksum",
			StatusCompliant,
			"IPv4 header checksum validation succeeded.",
		)
	} else {
		addResult(
			stats,
			"IPv4 header checksum",
			StatusUnverifiable,
			"IPv4 header checksum could not be verified.",
		)
	}
}

func analyzeUDPChecksum(
	packet gopacket.Packet,
	checksums analyzer.ChecksumStats,
	stats *Stats,
) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	udp := udpLayer.(*layers.UDP)

	isIPv6 := packet.Layer(layers.LayerTypeIPv6) != nil
	isIPv4 := packet.Layer(layers.LayerTypeIPv4) != nil

	if isIPv6 && udp.Checksum == 0 {
		addResult(
			stats,
			"IPv6 UDP checksum presence",
			StatusNonCompliant,
			"UDP over IPv6 has a zero checksum.",
		)
		return
	}

	if isIPv4 && udp.Checksum == 0 {
		addResult(
			stats,
			"IPv4 UDP checksum presence",
			StatusCompliant,
			"UDP checksum is omitted, which is permitted for IPv4.",
		)
		return
	}

	if checksums.UDP.Invalid > 0 {
		addResult(
			stats,
			"UDP checksum validity",
			StatusNonCompliant,
			"At least one UDP checksum was invalid.",
		)
		return
	}

	if checksums.UDP.Valid > 0 {
		addResult(
			stats,
			"UDP checksum validity",
			StatusCompliant,
			"UDP checksum validation succeeded.",
		)
		return
	}

	addResult(
		stats,
		"UDP checksum validity",
		StatusUnverifiable,
		"UDP checksum could not be verified.",
	)
}

func analyzeTCPFlags(
	packet gopacket.Packet,
	stats *Stats,
) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp := tcpLayer.(*layers.TCP)

	// SYN and FIN simultaneously is treated as a suspicious /
	// non-standard combination for this prototype.
	if tcp.SYN && tcp.FIN {
		addResult(
			stats,
			"TCP SYN/FIN combination",
			StatusNonCompliant,
			"TCP SYN and FIN flags are both set.",
		)
	} else {
		addResult(
			stats,
			"TCP SYN/FIN combination",
			StatusCompliant,
			"TCP SYN and FIN are not simultaneously set.",
		)
	}

	// SYN and RST together is also treated as invalid for
	// normal TCP operation.
	if tcp.SYN && tcp.RST {
		addResult(
			stats,
			"TCP SYN/RST combination",
			StatusNonCompliant,
			"TCP SYN and RST flags are both set.",
		)
	} else {
		addResult(
			stats,
			"TCP SYN/RST combination",
			StatusCompliant,
			"TCP SYN and RST are not simultaneously set.",
		)
	}
}
