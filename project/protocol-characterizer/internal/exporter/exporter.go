package exporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"protocol-characterizer/internal/anonymizer"
	"protocol-characterizer/internal/capture"
	"protocol-characterizer/internal/performance"
)

type FlowExport struct {
	Protocol        string `json:"protocol"`
	SourceIP        string `json:"source_ip"`
	SourcePort      uint16 `json:"source_port"`
	DestinationIP   string `json:"destination_ip"`
	DestinationPort uint16 `json:"destination_port"`
	Session         int    `json:"session"`
	Packets         int    `json:"packets"`
	Bytes           int64  `json:"bytes"`

	DurationSeconds   float64 `json:"duration_seconds"`
	MinimumPacketSize int     `json:"minimum_packet_size"`
	MaximumPacketSize int     `json:"maximum_packet_size"`
	AveragePacketSize float64 `json:"average_packet_size"`
	PacketsPerSecond  float64 `json:"packets_per_second"`
	BytesPerSecond    float64 `json:"bytes_per_second"`

	AverageInterArrival *float64 `json:"average_inter_arrival_seconds,omitempty"`
}

type CaptureExport struct {
	TotalPackets    int   `json:"total_packets"`
	TotalBytes      int64 `json:"total_bytes"`
	EthernetPackets int   `json:"ethernet_packets"`
	IPv4Packets     int   `json:"ipv4_packets"`
	IPv6Packets     int   `json:"ipv6_packets"`
	TCPPackets      int   `json:"tcp_packets"`
	UDPPackets      int   `json:"udp_packets"`
	TotalFlows      int   `json:"total_flows"`
	UniqueFiveTuple int   `json:"unique_five_tuples"`
}

type PortCountExport struct {
	Port    uint16 `json:"port"`
	Packets int    `json:"packets"`
}

type PortPairExport struct {
	Protocol        string `json:"protocol"`
	SourcePort      uint16 `json:"source_port"`
	DestinationPort uint16 `json:"destination_port"`
	Packets         int    `json:"packets"`
}

type ServiceExport struct {
	Service string `json:"service"`
	Packets int    `json:"packets"`
}

type PortsExport struct {
	SourcePorts      []PortCountExport `json:"source_ports"`
	DestinationPorts []PortCountExport `json:"destination_ports"`
	PortPairs        []PortPairExport  `json:"port_pairs"`
	InferredServices []ServiceExport   `json:"inferred_services"`
}

type JSONExport struct {
	AnalysisMode string                     `json:"analysis_mode"`
	Capture      CaptureExport              `json:"capture"`
	Flows        []FlowExport               `json:"flows"`
	TCPFlags     any                        `json:"tcp_flags"`
	TCPOptions   any                        `json:"tcp_options"`
	ECN          any                        `json:"ecn"`
	Checksums    any                        `json:"checksums"`
	Ports        PortsExport                `json:"ports"`
	IP           any                        `json:"ip"`
	Compliance   any                        `json:"compliance"`
	Statistics   capture.StatisticalSummary `json:"statistics"`
	Performance  performance.Metrics        `json:"performance"`
}

func ExportAll(
	summary capture.Summary,
	performanceMetrics performance.Metrics,
	analysisMode string,
	anon *anonymizer.Anonymizer,
	outputDirectory string,
) error {
	if err := os.MkdirAll(outputDirectory, 0755); err != nil {
		return fmt.Errorf(
			"could not create output directory: %w",
			err,
		)
	}

	jsonFilename := filepath.Join(
		outputDirectory,
		"results.json",
	)

	csvFilename := filepath.Join(
		outputDirectory,
		"flows.csv",
	)

	if err := ExportJSON(
		summary,
		performanceMetrics,
		analysisMode,
		anon,
		jsonFilename,
	); err != nil {
		return err
	}

	if err := ExportFlowsCSV(
		summary,
		anon,
		csvFilename,
	); err != nil {
		return err
	}

	return nil
}

func ExportJSON(
	summary capture.Summary,
	performanceMetrics performance.Metrics,
	analysisMode string,
	anon *anonymizer.Anonymizer,
	filename string,
) error {
	export := JSONExport{
		AnalysisMode: analysisMode,

		Capture: CaptureExport{
			TotalPackets:    summary.TotalPackets,
			TotalBytes:      summary.TotalBytes,
			EthernetPackets: summary.EthernetPackets,
			IPv4Packets:     summary.IPv4Packets,
			IPv6Packets:     summary.IPv6Packets,
			TCPPackets:      summary.TCPPackets,
			UDPPackets:      summary.UDPPackets,
			TotalFlows:      summary.TotalFlows,
			UniqueFiveTuple: len(summary.Flows),
		},

		Flows: buildFlowExports(
			summary,
			anon,
		),

		TCPFlags: summary.TCPFlags,

		TCPOptions: summary.TCPOptions,

		ECN: summary.ECN,

		Checksums: summary.Checksums,

		Ports: buildPortsExport(
			summary,
		),

		IP: summary.IP,

		Compliance: summary.Compliance,

		Statistics: summary.Statistics,

		Performance: performanceMetrics,
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf(
			"could not create JSON output: %w",
			err,
		)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)

	encoder.SetIndent(
		"",
		"  ",
	)

	if err := encoder.Encode(export); err != nil {
		return fmt.Errorf(
			"could not write JSON output: %w",
			err,
		)
	}

	return nil
}

func ExportFlowsCSV(
	summary capture.Summary,
	anon *anonymizer.Anonymizer,
	filename string,
) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf(
			"could not create CSV output: %w",
			err,
		)
	}
	defer file.Close()

	writer := csv.NewWriter(file)

	header := []string{
		"protocol",
		"source_ip",
		"source_port",
		"destination_ip",
		"destination_port",
		"session",
		"packets",
		"bytes",
		"duration_seconds",
		"minimum_packet_size",
		"maximum_packet_size",
		"average_packet_size",
		"packets_per_second",
		"bytes_per_second",
		"average_inter_arrival_seconds",
	}

	if err := writer.Write(header); err != nil {
		return fmt.Errorf(
			"could not write CSV header: %w",
			err,
		)
	}

	flows := buildFlowExports(
		summary,
		anon,
	)

	for _, item := range flows {
		averageInterArrival := ""

		if item.AverageInterArrival != nil {
			averageInterArrival =
				strconv.FormatFloat(
					*item.AverageInterArrival,
					'f',
					6,
					64,
				)
		}

		row := []string{
			item.Protocol,

			item.SourceIP,

			strconv.Itoa(
				int(item.SourcePort),
			),

			item.DestinationIP,

			strconv.Itoa(
				int(item.DestinationPort),
			),

			strconv.Itoa(
				item.Session,
			),

			strconv.Itoa(
				item.Packets,
			),

			strconv.FormatInt(
				item.Bytes,
				10,
			),

			strconv.FormatFloat(
				item.DurationSeconds,
				'f',
				6,
				64,
			),

			strconv.Itoa(
				item.MinimumPacketSize,
			),

			strconv.Itoa(
				item.MaximumPacketSize,
			),

			strconv.FormatFloat(
				item.AveragePacketSize,
				'f',
				6,
				64,
			),

			strconv.FormatFloat(
				item.PacketsPerSecond,
				'f',
				6,
				64,
			),

			strconv.FormatFloat(
				item.BytesPerSecond,
				'f',
				6,
				64,
			),

			averageInterArrival,
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf(
				"could not write CSV row: %w",
				err,
			)
		}
	}

	writer.Flush()

	if err := writer.Error(); err != nil {
		return fmt.Errorf(
			"could not finish CSV output: %w",
			err,
		)
	}

	return nil
}

func buildFlowExports(
	summary capture.Summary,
	anon *anonymizer.Anonymizer,
) []FlowExport {
	flows := make([]FlowExport, 0)

	for _, records := range summary.Flows {
		for sessionNumber, record := range records {
			var averageInterArrival *float64

			if record.InterArrivalCount > 0 {
				value :=
					record.AverageInterArrival().
						Seconds()

				averageInterArrival = &value
			}

			flows = append(
				flows,
				FlowExport{
					Protocol: record.Key.Protocol,

					SourceIP: anon.IP(
						record.Key.SourceIP,
					),

					SourcePort: record.Key.SourcePort,

					DestinationIP: anon.IP(
						record.Key.DestinationIP,
					),

					DestinationPort: record.Key.DestinationPort,

					Session: sessionNumber + 1,

					Packets: record.PacketCount,

					Bytes: record.ByteCount,

					DurationSeconds: record.Duration().
						Seconds(),

					MinimumPacketSize: record.MinPacketSize,

					MaximumPacketSize: record.MaxPacketSize,

					AveragePacketSize: record.AveragePacketSize(),

					PacketsPerSecond: record.PacketsPerSecond(),

					BytesPerSecond: record.BytesPerSecond(),

					AverageInterArrival: averageInterArrival,
				},
			)
		}
	}

	sort.Slice(
		flows,
		func(i, j int) bool {
			if flows[i].Protocol != flows[j].Protocol {
				return flows[i].Protocol <
					flows[j].Protocol
			}

			if flows[i].SourceIP != flows[j].SourceIP {
				return flows[i].SourceIP <
					flows[j].SourceIP
			}

			if flows[i].SourcePort != flows[j].SourcePort {
				return flows[i].SourcePort <
					flows[j].SourcePort
			}

			if flows[i].DestinationIP != flows[j].DestinationIP {
				return flows[i].DestinationIP <
					flows[j].DestinationIP
			}

			if flows[i].DestinationPort !=
				flows[j].DestinationPort {
				return flows[i].DestinationPort <
					flows[j].DestinationPort
			}

			return flows[i].Session <
				flows[j].Session
		},
	)

	return flows
}

func buildPortsExport(
	summary capture.Summary,
) PortsExport {
	result := PortsExport{
		SourcePorts: make([]PortCountExport, 0),

		DestinationPorts: make([]PortCountExport, 0),

		PortPairs: make([]PortPairExport, 0),

		InferredServices: make([]ServiceExport, 0),
	}

	for port, count := range summary.Ports.SourcePorts {
		result.SourcePorts = append(
			result.SourcePorts,
			PortCountExport{
				Port:    port,
				Packets: count,
			},
		)
	}

	sort.Slice(
		result.SourcePorts,
		func(i, j int) bool {
			return result.SourcePorts[i].Port <
				result.SourcePorts[j].Port
		},
	)

	for port, count := range summary.Ports.DestinationPorts {
		result.DestinationPorts = append(
			result.DestinationPorts,
			PortCountExport{
				Port:    port,
				Packets: count,
			},
		)
	}

	sort.Slice(
		result.DestinationPorts,
		func(i, j int) bool {
			return result.DestinationPorts[i].Port <
				result.DestinationPorts[j].Port
		},
	)

	for pair, count := range summary.Ports.PortPairs {
		result.PortPairs = append(
			result.PortPairs,
			PortPairExport{
				Protocol: pair.Protocol,

				SourcePort: pair.SourcePort,

				DestinationPort: pair.DestinationPort,

				Packets: count,
			},
		)
	}

	sort.Slice(
		result.PortPairs,
		func(i, j int) bool {
			if result.PortPairs[i].Protocol !=
				result.PortPairs[j].Protocol {
				return result.PortPairs[i].Protocol <
					result.PortPairs[j].Protocol
			}

			if result.PortPairs[i].SourcePort !=
				result.PortPairs[j].SourcePort {
				return result.PortPairs[i].SourcePort <
					result.PortPairs[j].SourcePort
			}

			return result.PortPairs[i].DestinationPort <
				result.PortPairs[j].DestinationPort
		},
	)

	for service, count := range summary.Ports.ServiceCounts {
		result.InferredServices = append(
			result.InferredServices,
			ServiceExport{
				Service: service,
				Packets: count,
			},
		)
	}

	sort.Slice(
		result.InferredServices,
		func(i, j int) bool {
			return result.InferredServices[i].Service <
				result.InferredServices[j].Service
		},
	)

	return result
}
