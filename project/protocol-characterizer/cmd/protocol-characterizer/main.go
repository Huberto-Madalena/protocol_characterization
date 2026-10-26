package main

import (
	"fmt"
	"os"
	"strings"

	"protocol-characterizer/internal/anonymizer"
	"protocol-characterizer/internal/capture"
	"protocol-characterizer/internal/config"
	"protocol-characterizer/internal/exporter"
	"protocol-characterizer/internal/performance"
	statspkg "protocol-characterizer/internal/stats"
)

func main() {
	fmt.Println("Protocol Characterizer")
	fmt.Println("----------------------")

	if len(os.Args) < 2 {
		printUsage()
		return
	}

	filename := os.Args[1]

	/*
		Full analysis remains the default so that existing commands such as

		    protocol-characterizer capture.pcap

		continue to behave as before.

		An experimental configuration can optionally be supplied as the
		second argument.
	*/
	mode := "full"

	if len(os.Args) >= 3 {
		mode = strings.ToLower(os.Args[2])
	}

	cfg, ok := config.FromName(mode)
	if !ok {
		fmt.Printf("Error: unknown analysis mode %q.\n\n", mode)
		printUsage()
		return
	}

	if len(os.Args) > 3 {
		fmt.Println("Error: too many command-line arguments.")
		fmt.Println()
		printUsage()
		return
	}

	// Temporary deterministic key for development/testing.
	// Later this should come from CLI/configuration/environment.
	anon := anonymizer.New("protocol-characterizer-default-key")

	fmt.Printf("Reading: %s\n", filename)
	fmt.Printf("Analysis mode: %s\n\n", cfg.Name)

	/*
		Measure only the PCAP analysis phase.

		Console rendering and structured export are intentionally excluded
		from the measurement so that experimental runs measure the analysis
		engine itself.
	*/
	performanceStart := performance.Start()

	summary, err := capture.ReadPCAP(
		filename,
		cfg,
	)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	performanceMetrics := performance.Stop(
		performanceStart,
		filename,
		summary.TotalPackets,
		summary.TotalBytes,
		summary.TotalFlows,
	)

	printCaptureSummary(summary)

	if cfg.Flows {
		printFlows(summary, anon)
	}

	printMACAddresses(summary, anon)

	if cfg.Ports {
		printPortAnalysis(summary)
	}

	if cfg.IP {
		printIPCharacterisation(summary)
	}

	if cfg.TCPFlags {
		printTCPFlags(summary)
	}

	if cfg.TCPOptions {
		printTCPOptions(summary)
	}

	if cfg.ECN {
		printECN(summary)
	}

	if cfg.Checksums || cfg.Compliance {
		printChecksums(summary)
	}

	if cfg.Compliance {
		printCompliance(summary)
	}

	if cfg.Statistics {
		printStatistics(summary)
	}

	printPerformanceMetrics(performanceMetrics)

	/*
		Export structured results.

		JSON contains the available capture-level characterisation,
		statistical summaries, performance metrics, and analysis mode.

		CSV contains reconstructed flow sessions when flow analysis is
		enabled. In configurations without flow analysis the CSV contains
		no flow records.

		IP addresses are anonymised before export.
	*/
	err = exporter.ExportAll(
		summary,
		performanceMetrics,
		cfg.Name,
		anon,
		"output",
	)
	if err != nil {
		fmt.Println("\nExport Error:", err)
		return
	}

	fmt.Println("\nExport Complete")
	fmt.Println("---------------")
	fmt.Println("JSON : output/results.json")
	fmt.Println("CSV  : output/flows.csv")
}

func printUsage() {
	fmt.Println(
		"Usage: protocol-characterizer <pcap-file> [mode]",
	)
	fmt.Println()
	fmt.Println("Available analysis modes:")
	fmt.Println("  baseline    Basic decoding and protocol counts only")
	fmt.Println("  checksums   Baseline + checksum analysis")
	fmt.Println("  ecn         Baseline + ECN analysis")
	fmt.Println("  compliance  Baseline + checksums + compliance")
	fmt.Println("  flows       Baseline + flow reconstruction + statistics")
	fmt.Println("  full        All implemented analyses (default)")
}

func printCaptureSummary(summary capture.Summary) {
	fmt.Println("Capture Summary")
	fmt.Println("---------------")
	fmt.Printf("Total packets    : %d\n", summary.TotalPackets)
	fmt.Printf("Total bytes      : %d\n", summary.TotalBytes)
	fmt.Printf("Ethernet packets : %d\n", summary.EthernetPackets)
	fmt.Printf("IPv4 packets     : %d\n", summary.IPv4Packets)
	fmt.Printf("IPv6 packets     : %d\n", summary.IPv6Packets)
	fmt.Printf("TCP packets      : %d\n", summary.TCPPackets)
	fmt.Printf("UDP packets      : %d\n", summary.UDPPackets)
	fmt.Printf("Total flows      : %d\n", summary.TotalFlows)
	fmt.Printf("Unique 5-tuples  : %d\n", len(summary.Flows))
}

func printFlows(
	summary capture.Summary,
	anon *anonymizer.Anonymizer,
) {
	fmt.Println("\nFlows")
	fmt.Println("-----")

	if summary.TotalFlows == 0 {
		fmt.Println("No TCP/UDP flows reconstructed.")
		return
	}

	flowNumber := 1

	for _, records := range summary.Flows {
		for sessionNumber, record := range records {
			fmt.Printf(
				"Flow %d | Session %d\n",
				flowNumber,
				sessionNumber+1,
			)

			fmt.Printf(
				"%s %s:%d -> %s:%d\n",
				record.Key.Protocol,
				anon.IP(record.Key.SourceIP),
				record.Key.SourcePort,
				anon.IP(record.Key.DestinationIP),
				record.Key.DestinationPort,
			)

			fmt.Printf(
				"  Packets              : %d\n",
				record.PacketCount,
			)
			fmt.Printf(
				"  Bytes                : %d\n",
				record.ByteCount,
			)
			fmt.Printf(
				"  Duration             : %s\n",
				record.Duration(),
			)
			fmt.Printf(
				"  Min packet size      : %d bytes\n",
				record.MinPacketSize,
			)
			fmt.Printf(
				"  Max packet size      : %d bytes\n",
				record.MaxPacketSize,
			)
			fmt.Printf(
				"  Average packet size  : %.2f bytes\n",
				record.AveragePacketSize(),
			)
			fmt.Printf(
				"  Packets/second       : %.2f\n",
				record.PacketsPerSecond(),
			)
			fmt.Printf(
				"  Bytes/second         : %.2f\n",
				record.BytesPerSecond(),
			)

			if record.InterArrivalCount > 0 {
				fmt.Printf(
					"  Avg inter-arrival    : %s\n",
					record.AverageInterArrival(),
				)

				fmt.Printf(
					"  Min inter-arrival    : %s\n",
					record.MinInterArrival,
				)

				fmt.Printf(
					"  Max inter-arrival    : %s\n",
					record.MaxInterArrival,
				)
			} else {
				fmt.Println("  Avg inter-arrival    : N/A")
				fmt.Println("  Min inter-arrival    : N/A")
				fmt.Println("  Max inter-arrival    : N/A")
			}

			fmt.Println()
			flowNumber++
		}
	}
}

func printMACAddresses(
	summary capture.Summary,
	anon *anonymizer.Anonymizer,
) {
	fmt.Println("\nMAC Addresses")
	fmt.Println("-------------")

	if len(summary.MACAddresses) == 0 {
		fmt.Println("No Ethernet MAC addresses detected.")
		return
	}

	for address, count := range summary.MACAddresses {
		fmt.Printf(
			"%s | Observations: %d\n",
			anon.MAC(address),
			count,
		)
	}
}

func printPortAnalysis(summary capture.Summary) {
	fmt.Println("\nPort Analysis")
	fmt.Println("-------------")

	fmt.Println("Source Ports")

	if len(summary.Ports.SourcePorts) == 0 {
		fmt.Println("  None detected.")
	} else {
		for port, count := range summary.Ports.SourcePorts {
			fmt.Printf(
				"  %d : %d packet(s)\n",
				port,
				count,
			)
		}
	}

	fmt.Println("\nDestination Ports")

	if len(summary.Ports.DestinationPorts) == 0 {
		fmt.Println("  None detected.")
	} else {
		for port, count := range summary.Ports.DestinationPorts {
			fmt.Printf(
				"  %d : %d packet(s)\n",
				port,
				count,
			)
		}
	}

	fmt.Println("\nPort Pairs")

	if len(summary.Ports.PortPairs) == 0 {
		fmt.Println("  None detected.")
	} else {
		for pair, count := range summary.Ports.PortPairs {
			fmt.Printf(
				"  %s %d -> %d : %d packet(s)\n",
				pair.Protocol,
				pair.SourcePort,
				pair.DestinationPort,
				count,
			)
		}
	}

	fmt.Println("\nInferred Services")

	if len(summary.Ports.ServiceCounts) == 0 {
		fmt.Println(
			"  No known service inferred from observed ports.",
		)
	} else {
		for service, count := range summary.Ports.ServiceCounts {
			fmt.Printf(
				"  %s : %d packet(s)\n",
				service,
				count,
			)
		}
	}

	fmt.Println(
		"  Note: Service names are inferred from port usage only.",
	)
}

func printIPCharacterisation(summary capture.Summary) {
	fmt.Println("\nIP Characterisation")
	fmt.Println("-------------------")

	fmt.Println("IPv4")
	fmt.Printf(
		"  Packets          : %d\n",
		summary.IP.IPv4Packets,
	)
	fmt.Printf(
		"  Fragmented       : %d\n",
		summary.IP.IPv4Fragmented,
	)
	fmt.Printf(
		"  With options     : %d\n",
		summary.IP.IPv4WithOptions,
	)

	if summary.IP.IPv4TTLCount > 0 {
		fmt.Printf(
			"  Average TTL      : %.2f\n",
			summary.IP.AverageIPv4TTL(),
		)
		fmt.Printf(
			"  Minimum TTL      : %d\n",
			summary.IP.IPv4TTLMin,
		)
		fmt.Printf(
			"  Maximum TTL      : %d\n",
			summary.IP.IPv4TTLMax,
		)
	} else {
		fmt.Println("  Average TTL      : N/A")
		fmt.Println("  Minimum TTL      : N/A")
		fmt.Println("  Maximum TTL      : N/A")
	}

	fmt.Println("IPv6")
	fmt.Printf(
		"  Packets          : %d\n",
		summary.IP.IPv6Packets,
	)
	fmt.Printf(
		"  Fragmented       : %d\n",
		summary.IP.IPv6Fragmented,
	)

	if summary.IP.IPv6HopLimitCount > 0 {
		fmt.Printf(
			"  Average Hop Limit: %.2f\n",
			summary.IP.AverageIPv6HopLimit(),
		)
		fmt.Printf(
			"  Minimum Hop Limit: %d\n",
			summary.IP.IPv6HopLimitMin,
		)
		fmt.Printf(
			"  Maximum Hop Limit: %d\n",
			summary.IP.IPv6HopLimitMax,
		)
	} else {
		fmt.Println("  Average Hop Limit: N/A")
		fmt.Println("  Minimum Hop Limit: N/A")
		fmt.Println("  Maximum Hop Limit: N/A")
	}
}

func printTCPFlags(summary capture.Summary) {
	fmt.Println("\nTCP Flags")
	fmt.Println("---------")
	fmt.Printf("SYN : %d\n", summary.TCPFlags.SYN)
	fmt.Printf("ACK : %d\n", summary.TCPFlags.ACK)
	fmt.Printf("FIN : %d\n", summary.TCPFlags.FIN)
	fmt.Printf("RST : %d\n", summary.TCPFlags.RST)
	fmt.Printf("PSH : %d\n", summary.TCPFlags.PSH)
	fmt.Printf("URG : %d\n", summary.TCPFlags.URG)
	fmt.Printf("ECE : %d\n", summary.TCPFlags.ECE)
	fmt.Printf("CWR : %d\n", summary.TCPFlags.CWR)
}

func printTCPOptions(summary capture.Summary) {
	fmt.Println("\nTCP Options")
	fmt.Println("-----------")
	fmt.Printf(
		"SACK permitted : %d\n",
		summary.TCPOptions.SACKPermitted,
	)
	fmt.Printf(
		"SACK blocks    : %d\n",
		summary.TCPOptions.SACKBlocks,
	)
	fmt.Printf(
		"Window scale   : %d\n",
		summary.TCPOptions.WindowScale,
	)
	fmt.Printf(
		"MSS            : %d\n",
		summary.TCPOptions.MSS,
	)
	fmt.Printf(
		"Timestamps     : %d\n",
		summary.TCPOptions.Timestamps,
	)
}

func printECN(summary capture.Summary) {
	fmt.Println("\nECN Analysis")
	fmt.Println("------------")
	fmt.Printf("Not-ECT : %d\n", summary.ECN.NotECT)
	fmt.Printf("ECT(0)  : %d\n", summary.ECN.ECT0)
	fmt.Printf("ECT(1)  : %d\n", summary.ECN.ECT1)
	fmt.Printf("CE      : %d\n", summary.ECN.CE)
	fmt.Printf("ECE     : %d\n", summary.ECN.ECE)
	fmt.Printf("CWR     : %d\n", summary.ECN.CWR)
}

func printChecksums(summary capture.Summary) {
	fmt.Println("\nChecksum Analysis")
	fmt.Println("-----------------")

	fmt.Println("IPv4 Header")
	fmt.Printf(
		"  Present      : %d\n",
		summary.Checksums.IPv4.Present,
	)
	fmt.Printf(
		"  Valid        : %d\n",
		summary.Checksums.IPv4.Valid,
	)
	fmt.Printf(
		"  Invalid      : %d\n",
		summary.Checksums.IPv4.Invalid,
	)
	fmt.Printf(
		"  Unverifiable : %d\n",
		summary.Checksums.IPv4.Unverifiable,
	)

	fmt.Println("TCP")
	fmt.Printf(
		"  Present      : %d\n",
		summary.Checksums.TCP.Present,
	)
	fmt.Printf(
		"  Valid        : %d\n",
		summary.Checksums.TCP.Valid,
	)
	fmt.Printf(
		"  Invalid      : %d\n",
		summary.Checksums.TCP.Invalid,
	)
	fmt.Printf(
		"  Unverifiable : %d\n",
		summary.Checksums.TCP.Unverifiable,
	)

	fmt.Println("UDP")
	fmt.Printf(
		"  Present      : %d\n",
		summary.Checksums.UDP.Present,
	)
	fmt.Printf(
		"  Absent       : %d\n",
		summary.Checksums.UDP.Absent,
	)
	fmt.Printf(
		"  Valid        : %d\n",
		summary.Checksums.UDP.Valid,
	)
	fmt.Printf(
		"  Invalid      : %d\n",
		summary.Checksums.UDP.Invalid,
	)
	fmt.Printf(
		"  Unverifiable : %d\n",
		summary.Checksums.UDP.Unverifiable,
	)
}

func printCompliance(summary capture.Summary) {
	fmt.Println("\nProtocol Compliance")
	fmt.Println("-------------------")

	fmt.Printf(
		"Compliant      : %d\n",
		summary.Compliance.Compliant,
	)
	fmt.Printf(
		"Non-compliant  : %d\n",
		summary.Compliance.NonCompliant,
	)
	fmt.Printf(
		"Unverifiable   : %d\n",
		summary.Compliance.Unverifiable,
	)
	fmt.Printf(
		"Not applicable : %d\n",
		summary.Compliance.NotApplicable,
	)

	fmt.Println("\nRule Results")

	if len(summary.Compliance.Results) == 0 {
		fmt.Println("  No compliance rules were applicable.")
	} else {
		for i, result := range summary.Compliance.Results {
			fmt.Printf(
				"  %d. %s\n",
				i+1,
				result.Name,
			)

			fmt.Printf(
				"     Status  : %s\n",
				result.Status,
			)

			fmt.Printf(
				"     Details : %s\n",
				result.Details,
			)
		}
	}

	fmt.Println(
		"  Note: Compliance results apply only to properties observable in the capture.",
	)
}

func printStatistics(summary capture.Summary) {
	fmt.Println("\nStatistical Summary")
	fmt.Println("-------------------")

	printStatisticalSummary(
		"Packet Size (bytes)",
		summary.Statistics.PacketSizes,
	)

	printStatisticalSummary(
		"Flow Duration (seconds)",
		summary.Statistics.FlowDurations,
	)

	printStatisticalSummary(
		"Packets per Flow",
		summary.Statistics.PacketsPerFlow,
	)

	printStatisticalSummary(
		"Bytes per Flow",
		summary.Statistics.BytesPerFlow,
	)

	printStatisticalSummary(
		"Average Packet Size per Flow (bytes)",
		summary.Statistics.AveragePacketSizes,
	)

	printStatisticalSummary(
		"Packets per Second",
		summary.Statistics.PacketsPerSecond,
	)

	printStatisticalSummary(
		"Bytes per Second",
		summary.Statistics.BytesPerSecond,
	)

	printStatisticalSummary(
		"Average Inter-arrival Time per Flow (seconds)",
		summary.Statistics.AverageInterArrivalTime,
	)

	fmt.Println(
		"Note: Inter-arrival statistics represent average inter-arrival time per eligible flow.",
	)
}

func printPerformanceMetrics(
	metrics performance.Metrics,
) {
	fmt.Println("\nPerformance Metrics")
	fmt.Println("-------------------")

	fmt.Printf(
		"Processing time       : %.6f seconds\n",
		metrics.ProcessingTimeSeconds,
	)

	fmt.Printf(
		"Input file size       : %d bytes\n",
		metrics.InputFileSizeBytes,
	)

	fmt.Printf(
		"Packets processed     : %d\n",
		metrics.PacketsProcessed,
	)

	fmt.Printf(
		"Bytes processed       : %d\n",
		metrics.BytesProcessed,
	)

	fmt.Printf(
		"Packets/second        : %.2f\n",
		metrics.PacketsPerSecond,
	)

	fmt.Printf(
		"Bytes/second          : %.2f\n",
		metrics.BytesPerSecond,
	)

	fmt.Printf(
		"Megabytes/second      : %.6f\n",
		metrics.MegabytesPerSecond,
	)

	fmt.Printf(
		"Heap allocation delta : %d bytes\n",
		metrics.HeapAllocationBytes,
	)

	fmt.Printf(
		"Total allocation      : %d bytes\n",
		metrics.TotalAllocationBytes,
	)

	fmt.Printf(
		"Flow count            : %d\n",
		metrics.FlowCount,
	)

	fmt.Println(
		"  Note: memory values are Go runtime allocation measurements, not exact OS peak memory.",
	)
}

func printStatisticalSummary(
	name string,
	summary statspkg.Summary,
) {
	fmt.Printf("\n%s\n", name)

	if summary.Count == 0 {
		fmt.Println("  Count                  : 0")
		fmt.Println("  No observations available.")
		return
	}

	fmt.Printf(
		"  Count                  : %d\n",
		summary.Count,
	)
	fmt.Printf(
		"  Mean                   : %.6f\n",
		summary.Mean,
	)
	fmt.Printf(
		"  Median                 : %.6f\n",
		summary.Median,
	)
	fmt.Printf(
		"  Standard deviation     : %.6f\n",
		summary.StandardDeviation,
	)
	fmt.Printf(
		"  Minimum                : %.6f\n",
		summary.Minimum,
	)
	fmt.Printf(
		"  Maximum                : %.6f\n",
		summary.Maximum,
	)
	fmt.Printf(
		"  25th percentile        : %.6f\n",
		summary.Percentile25,
	)
	fmt.Printf(
		"  75th percentile        : %.6f\n",
		summary.Percentile75,
	)
	fmt.Printf(
		"  95th percentile        : %.6f\n",
		summary.Percentile95,
	)
	fmt.Printf(
		"  99th percentile        : %.6f\n",
		summary.Percentile99,
	)

	fmt.Printf(
		"  Coefficient variation  : %.6f\n",
		summary.CoefficientVariation,
	)
}
