package capture

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"protocol-characterizer/internal/analyzer"
	"protocol-characterizer/internal/compliance"
	"protocol-characterizer/internal/config"
	"protocol-characterizer/internal/decoder"
	"protocol-characterizer/internal/flow"
	statspkg "protocol-characterizer/internal/stats"
)

const UDPInactivityTimeout = 30 * time.Second

type StatisticalSummary struct {
	PacketSizes             statspkg.Summary
	FlowDurations           statspkg.Summary
	PacketsPerFlow          statspkg.Summary
	BytesPerFlow            statspkg.Summary
	AveragePacketSizes      statspkg.Summary
	PacketsPerSecond        statspkg.Summary
	BytesPerSecond          statspkg.Summary
	AverageInterArrivalTime statspkg.Summary
}

type Summary struct {
	TotalPackets    int
	TotalBytes      int64
	EthernetPackets int
	IPv4Packets     int
	IPv6Packets     int
	TCPPackets      int
	UDPPackets      int
	TotalFlows      int

	Flows        map[flow.Key][]*flow.Record
	MACAddresses map[string]int

	TCPFlags   analyzer.TCPFlags
	TCPOptions analyzer.TCPOptions
	ECN        analyzer.ECNStats
	Checksums  analyzer.ChecksumStats
	Ports      analyzer.PortStats
	IP         analyzer.IPStats

	Compliance compliance.Stats
	Statistics StatisticalSummary
}

func ReadPCAP(
	filename string,
	cfg config.AnalysisConfig,
) (Summary, error) {
	var summary Summary

	summary.Flows = make(map[flow.Key][]*flow.Record)
	summary.MACAddresses = make(map[string]int)

	if cfg.Ports {
		summary.Ports = analyzer.InitPortStats()
	}

	/*
		Packet-size observations are retained only when statistical
		analysis is enabled.

		This avoids allocating one floating-point value per packet in
		experimental modes that do not require descriptive statistics.

		The full/statistics mode still uses an in-memory slice in the
		current prototype. For very large traces this will later be
		replaced by streaming statistics and bounded quantile
		estimation.
	*/
	var packetSizes []float64

	if cfg.Statistics {
		packetSizes = make([]float64, 0)
	}

	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return summary, fmt.Errorf(
			"could not open PCAP file: %w",
			err,
		)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)

	for packet := range packetSource.Packets() {
		summary.TotalPackets++

		metadata := packet.Metadata()

		packetSize := 0
		var timestamp time.Time

		if metadata != nil {
			packetSize = metadata.CaptureLength
			timestamp = metadata.Timestamp

			summary.TotalBytes += int64(packetSize)

			if cfg.Statistics {
				packetSizes = append(
					packetSizes,
					float64(packetSize),
				)
			}
		}

		/*
			Basic protocol decoding remains active in every
			configuration.

			This means the experimental baseline represents:

			    PCAP reading
			    + packet decoding
			    + basic protocol counting

			It does not represent raw disk I/O alone.

			Keeping this common decoding work in every configuration
			gives the feature-overhead experiments a consistent
			reference point.
		*/
		decoded := decoder.Decode(packet)

		// Ethernet protocol and MAC address observations.
		if decoded.HasEthernet {
			summary.EthernetPackets++

			sourceMAC := decoded.Ethernet.SrcMAC.String()
			destinationMAC := decoded.Ethernet.DstMAC.String()

			if sourceMAC != "" {
				summary.MACAddresses[sourceMAC]++
			}

			if destinationMAC != "" {
				summary.MACAddresses[destinationMAC]++
			}
		}

		// IP protocol counts.
		if decoded.HasIPv4 {
			summary.IPv4Packets++
		}

		if decoded.HasIPv6 {
			summary.IPv6Packets++
		}

		// Transport protocol counts.
		if decoded.HasTCP {
			summary.TCPPackets++
		}

		if decoded.HasUDP {
			summary.UDPPackets++
		}

		/*
			TCP flag characterisation.
		*/
		if cfg.TCPFlags {
			analyzer.AnalyzeTCPFlags(
				packet,
				&summary.TCPFlags,
			)
		}

		/*
			TCP option characterisation.
		*/
		if cfg.TCPOptions {
			analyzer.AnalyzeTCPOptions(
				packet,
				&summary.TCPOptions,
			)
		}

		/*
			Explicit Congestion Notification analysis.
		*/
		if cfg.ECN {
			analyzer.AnalyzeECN(
				packet,
				&summary.ECN,
			)
		}

		/*
			Checksum analysis.

			Compliance currently depends on per-packet checksum
			results. Therefore checksum analysis is also performed
			whenever compliance is enabled, even if a custom
			configuration accidentally enables Compliance without
			explicitly enabling Checksums.

			This protects the dependency at runtime rather than
			relying only on configuration construction.
		*/
		var packetChecksums analyzer.ChecksumStats

		if cfg.Checksums || cfg.Compliance {
			checksumsBefore := summary.Checksums

			analyzer.AnalyzeChecksums(
				packet,
				&summary.Checksums,
			)

			packetChecksums = checksumDifference(
				checksumsBefore,
				summary.Checksums,
			)
		}

		/*
			Port and service characterisation.
		*/
		if cfg.Ports {
			analyzer.AnalyzePorts(
				packet,
				&summary.Ports,
			)
		}

		/*
			IPv4 and IPv6 header characterisation.
		*/
		if cfg.IP {
			analyzer.AnalyzeIP(
				packet,
				&summary.IP,
			)
		}

		/*
			Packet-level protocol compliance analysis.
		*/
		if cfg.Compliance {
			compliance.AnalyzePacket(
				packet,
				packetChecksums,
				&summary.Compliance,
			)
		}

		/*
			Flow reconstruction is optional.

			When disabled, no 5-tuple extraction, flow-map lookup,
			flow allocation, session splitting, or per-flow
			statistical updates are performed.
		*/
		if !cfg.Flows {
			continue
		}

		/*
			Flow reconstruction requires timestamp information.

			Packet-level characterisation can still be performed
			without timestamp metadata, but timing-dependent flow
			analysis cannot.
		*/
		if metadata == nil {
			continue
		}

		key, ok := flow.GetKey(packet)
		if !ok {
			continue
		}

		records := summary.Flows[key]

		var record *flow.Record

		/*
			TCP:

			The current prototype groups packets sharing the same
			directional TCP 5-tuple into one flow record.

			TCP lifecycle handling using SYN, FIN, RST, inactivity,
			and connection reuse will be introduced later.

			UDP:

			UDP has no protocol-level connection establishment or
			termination. The prototype therefore uses an inactivity
			timeout to separate logical UDP sessions.

			If the same directional UDP 5-tuple reappears after
			more than 30 seconds of inactivity, a new logical
			session is created.
		*/
		if key.Protocol == "UDP" {
			if len(records) == 0 {
				record = newFlowRecord(key)

				summary.Flows[key] = append(
					summary.Flows[key],
					record,
				)

				summary.TotalFlows++
			} else {
				record = records[len(records)-1]

				idleTime := timestamp.Sub(
					record.LastPacketTime,
				)

				/*
					Out-of-order timestamps produce zero or negative
					intervals and therefore do not trigger a session
					split.
				*/
				if idleTime > UDPInactivityTimeout {
					record = newFlowRecord(key)

					summary.Flows[key] = append(
						summary.Flows[key],
						record,
					)

					summary.TotalFlows++
				}
			}
		} else {
			/*
				TCP currently uses one flow record per directional
				5-tuple.
			*/
			if len(records) == 0 {
				record = newFlowRecord(key)

				summary.Flows[key] = append(
					summary.Flows[key],
					record,
				)

				summary.TotalFlows++
			} else {
				record = records[0]
			}
		}

		/*
			Update:

			- packet count
			- byte count
			- timestamps
			- packet-size statistics
			- inter-arrival statistics
			- packet rate
			- byte rate
		*/
		record.AddPacket(
			timestamp,
			packetSize,
		)
	}

	/*
		Descriptive statistics are calculated only when explicitly
		enabled by the experimental configuration.

		In baseline, checksum-only, ECN-only and compliance-only
		configurations this post-processing stage is skipped.
	*/
	if cfg.Statistics {
		calculateStatistics(
			&summary,
			packetSizes,
		)
	}

	return summary, nil
}

func newFlowRecord(key flow.Key) *flow.Record {
	return &flow.Record{
		Key: key,
	}
}

/*
calculateStatistics converts completed packet and flow observations
into descriptive statistical summaries.

The resulting metrics can be printed, exported to JSON/CSV, and used
in experimental analysis.
*/
func calculateStatistics(
	summary *Summary,
	packetSizes []float64,
) {
	flowDurations := make([]float64, 0)
	packetsPerFlow := make([]float64, 0)
	bytesPerFlow := make([]float64, 0)
	averagePacketSizes := make([]float64, 0)
	packetsPerSecond := make([]float64, 0)
	bytesPerSecond := make([]float64, 0)
	averageInterArrivalTimes := make([]float64, 0)

	for _, records := range summary.Flows {
		for _, record := range records {
			flowDurations = append(
				flowDurations,
				record.Duration().Seconds(),
			)

			packetsPerFlow = append(
				packetsPerFlow,
				float64(record.PacketCount),
			)

			bytesPerFlow = append(
				bytesPerFlow,
				float64(record.ByteCount),
			)

			averagePacketSizes = append(
				averagePacketSizes,
				record.AveragePacketSize(),
			)

			packetsPerSecond = append(
				packetsPerSecond,
				record.PacketsPerSecond(),
			)

			bytesPerSecond = append(
				bytesPerSecond,
				record.BytesPerSecond(),
			)

			/*
				Only include inter-arrival observations for flows
				that contain at least one actual interval.

				A one-packet flow has no meaningful inter-arrival
				time and therefore must not be represented as zero.
			*/
			if record.InterArrivalCount > 0 {
				averageInterArrivalTimes = append(
					averageInterArrivalTimes,
					record.AverageInterArrival().Seconds(),
				)
			}
		}
	}

	summary.Statistics.PacketSizes =
		statspkg.Calculate(packetSizes)

	summary.Statistics.FlowDurations =
		statspkg.Calculate(flowDurations)

	summary.Statistics.PacketsPerFlow =
		statspkg.Calculate(packetsPerFlow)

	summary.Statistics.BytesPerFlow =
		statspkg.Calculate(bytesPerFlow)

	summary.Statistics.AveragePacketSizes =
		statspkg.Calculate(averagePacketSizes)

	summary.Statistics.PacketsPerSecond =
		statspkg.Calculate(packetsPerSecond)

	summary.Statistics.BytesPerSecond =
		statspkg.Calculate(bytesPerSecond)

	summary.Statistics.AverageInterArrivalTime =
		statspkg.Calculate(averageInterArrivalTimes)
}

/*
checksumDifference returns only the checksum observations contributed
by the current packet.

This prevents an invalid or unverifiable checksum observed in an
earlier packet from affecting the compliance classification of a later
packet.
*/
func checksumDifference(
	before analyzer.ChecksumStats,
	after analyzer.ChecksumStats,
) analyzer.ChecksumStats {
	return analyzer.ChecksumStats{
		IPv4: checksumResultDifference(
			before.IPv4,
			after.IPv4,
		),

		TCP: checksumResultDifference(
			before.TCP,
			after.TCP,
		),

		UDP: checksumResultDifference(
			before.UDP,
			after.UDP,
		),
	}
}

func checksumResultDifference(
	before analyzer.ChecksumResult,
	after analyzer.ChecksumResult,
) analyzer.ChecksumResult {
	return analyzer.ChecksumResult{
		Present: after.Present -
			before.Present,

		Absent: after.Absent -
			before.Absent,

		Valid: after.Valid -
			before.Valid,

		Invalid: after.Invalid -
			before.Invalid,

		Unverifiable: after.Unverifiable -
			before.Unverifiable,
	}
}
