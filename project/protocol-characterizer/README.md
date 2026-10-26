# Protocol Characterizer

This is a Go-based packet-level protocol characterisation framework for analysing PCAP network traces.
You can read more about the Go language here:

https://go.dev/doc/


The framework provides configurable analysis of TCP, UDP, IPv4, and IPv6 traffic, including flow reconstruction, TCP flags and options, Explicit Congestion Notification (ECN), checksum validation, port and service analysis, protocol compliance checks, descriptive statistics, anonymisation, and performance measurement.

The implementation was developed as part of the research project **“Protocol Characterisation at the Packet Level.”**

---

## 1. Features

The current implementation supports:

- Offline PCAP analysis
- Ethernet packet identification
- IPv4 and IPv6 identification
- TCP and UDP characterisation
- TCP flag analysis
- TCP option analysis
- ECN analysis
- IPv4, TCP, and UDP checksum validation
- Source and destination port analysis
- Port-pair analysis
- Port-based service inference
- IPv4 fragmentation detection
- IPv4 option detection
- IPv4 TTL statistics
- IPv6 hop-limit statistics
- TCP/UDP flow reconstruction
- UDP inactivity-based flow separation
- Packet and flow descriptive statistics
- Protocol compliance checks
- Deterministic IP address anonymisation
- Deterministic MAC address anonymisation
- Runtime performance measurement
- JSON result export
- CSV flow export
- Configurable analysis modes for feature-level experiments

---

## 2. Requirements

The following software is required.

### Go

The project was developed and tested using:

```text
Go 1.27.1
```

Check whether Go is installed:

```powershell
go version
```

Example:

```text
go version go1.27.1 windows/amd64
```

If Go is not installed, install an appropriate recent Go version before continuing.

### Git

Git is recommended when cloning the source-code repository.

Check whether Git is installed:

```powershell
git --version
```

### Wireshark — Optional

Wireshark is not required to compile or run the framework.

It is useful for:

- creating PCAP captures;
- inspecting packets independently;
- validating packet fields;
- converting `pcapng` captures to standard `pcap`.

The framework has primarily been tested using standard `.pcap` files.

---

## 3. Project Structure

```text
protocol-characterizer/
├── cmd/
│   └── protocol-characterizer/
│       └── main.go
│
├── internal/
│   ├── analyzer/
│   │   ├── checksum.go
│   │   ├── ecn.go
│   │   ├── ip.go
│   │   ├── ports.go
│   │   ├── tcp.go
│   │   └── tcp_options.go
│   │
│   ├── anonymizer/
│   │   └── anonymizer.go
│   │
│   ├── capture/
│   │   └── reader.go
│   │
│   ├── compliance/
│   │   └── compliance.go
│   │
│   ├── config/
│   │   └── config.go
│   │
│   ├── decoder/
│   │   └── decoder.go
│   │
│   ├── exporter/
│   │   └── exporter.go
│   │
│   ├── flow/
│   │   └── flow.go
│   │
│   ├── performance/
│   │   └── performance.go
│   │
│   └── stats/
│       └── stats.go
│
├── data/
├── output/
├── go.mod
├── go.sum
└── README.md
```

---

## 4. Installation and Environment Setup

### Step 1 — Obtain the source code

If the project is provided as a ZIP archive, extract it and open PowerShell in the extracted `protocol-characterizer` directory.

If the project is hosted in a Git repository, clone it:

```powershell
git clone <repository-url>
cd protocol-characterizer
```

Replace `<repository-url>` with the actual repository URL.

---

### Step 2 — Confirm Go installation

Run:

```powershell
go version
```

The project was developed with Go 1.27.1 on Windows AMD64.

---

### Step 3 — Install project dependencies

The main external packet-processing dependency is:

```text
github.com/google/gopacket
```

Dependencies are defined by `go.mod` and `go.sum`.

From the project root, run:

```powershell
go mod download
```

Then:

```powershell
go mod tidy
```

This downloads and verifies the required Go modules.

To inspect the dependency list:

```powershell
go list -m all
```

---

### Step 4 — Format the source code

Run:

```powershell
go fmt ./...
```

---

### Step 5 — Build the application

From the project root:

```powershell
go build .\cmd\protocol-characterizer
```

On Windows, this should produce an executable such as:

```text
protocol-characterizer.exe
```

in the project root.

If the command completes without an error, the project has built successfully.

---

## 5. Preparing PCAP Data

Place PCAP files inside:

```text
data/
```

For example:

```text
data/
├── benchmark.pcap
├── ETH_IPv4_TCP_syn.pcap
├── ETH_IPv4_UDP_dns.pcap
└── IPv4-DHCP-Sequence.pcap
```

The framework has been validated primarily with standard `.pcap` captures.

If Wireshark creates a `.pcapng` file, it can be converted by opening the capture in Wireshark and using:

```text
File → Save As
```

Then select the standard PCAP format and save the resulting file with a `.pcap` extension.

---

## 6. Running the Framework

The basic command syntax is:

```powershell
go run .\cmd\protocol-characterizer <pcap-file> [mode]
```

For example:

```powershell
go run .\cmd\protocol-characterizer .\data\benchmark.pcap full
```

If no mode is specified, `full` is used by default:

```powershell
go run .\cmd\protocol-characterizer .\data\benchmark.pcap
```

---

## 7. Analysis Modes

The framework supports six configurations.

| Mode | Purpose |
|---|---|
| `baseline` | Basic packet decoding and protocol counts |
| `checksums` | Baseline plus checksum analysis |
| `ecn` | Baseline plus ECN analysis |
| `compliance` | Baseline plus checksum and protocol compliance analysis |
| `flows` | Baseline plus flow reconstruction and statistics |
| `full` | Enables all implemented analysis components |

### Baseline

```powershell
go run .\cmd\protocol-characterizer .\data\benchmark.pcap baseline
```

The baseline configuration performs the common packet-reading, decoding, protocol-counting, and basic capture-processing work without enabling the optional feature analyses.

It should therefore be interpreted as the framework's **decoding/counting baseline**, rather than a raw disk-I/O benchmark.

### Checksum analysis

```powershell
go run .\cmd\protocol-characterizer .\data\benchmark.pcap checksums
```

This enables checksum characterisation in addition to baseline processing.

### ECN analysis

```powershell
go run .\cmd\protocol-characterizer .\data\benchmark.pcap ecn
```

This enables Explicit Congestion Notification characterisation.

### Compliance analysis

```powershell
go run .\cmd\protocol-characterizer .\data\benchmark.pcap compliance
```

This enables checksum analysis and the currently implemented protocol compliance rules.

### Flow analysis

```powershell
go run .\cmd\protocol-characterizer .\data\benchmark.pcap flows
```

This enables flow reconstruction and descriptive statistics.

### Full analysis

```powershell
go run .\cmd\protocol-characterizer .\data\benchmark.pcap full
```

This enables all currently implemented analyses.

---

## 8. Example

Run:

```powershell
go run .\cmd\protocol-characterizer .\data\IPv4-DHCP-Sequence.pcap full
```

The terminal output includes sections such as:

```text
Protocol Characterizer
----------------------
Reading: .\data\IPv4-DHCP-Sequence.pcap
Analysis mode: full

Capture Summary
---------------
Total packets    : ...
Total bytes      : ...
Ethernet packets : ...
IPv4 packets     : ...
IPv6 packets     : ...
TCP packets      : ...
UDP packets      : ...
Total flows      : ...

...

Performance Metrics
-------------------
Processing time       : ...
Input file size       : ...
Packets processed     : ...
Bytes processed       : ...
Packets/second        : ...
Megabytes/second      : ...
Heap allocation delta : ...
Total allocation      : ...
Flow count            : ...
```

The exact values depend on the supplied capture.

---

## 9. Output Files

After successful execution, results are written to:

```text
output/
```

The principal files are:

```text
output/results.json
output/flows.csv
```

### JSON

`results.json` stores structured analysis results, including the selected analysis mode.

For example:

```json
{
  "analysis_mode": "checksums",
  "capture": {
    "total_packets": 4,
    "total_bytes": 1312,
    "ethernet_packets": 4,
    "ipv4_packets": 4,
    "ipv6_packets": 0,
    "tcp_packets": 0,
    "udp_packets": 4,
    "total_flows": 0,
    "unique_five_tuples": 0
  }
}
```

Depending on the selected mode, the JSON output can additionally contain results for:

- flows;
- TCP flags;
- TCP options;
- ECN;
- checksums;
- ports;
- IP characteristics;
- compliance;
- descriptive statistics;
- performance metrics.

### CSV

`flows.csv` contains reconstructed TCP/UDP flow information when flow analysis is enabled.

The output files are overwritten by subsequent executions. Copy or rename them when individual run results need to be retained.

---

## 10. Anonymisation

The framework anonymises IP and MAC addresses before displaying/exporting identifying network addresses.

The current implementation uses deterministic HMAC-SHA256-based aliases. This allows repeated occurrences of the same identifier to be recognised without directly displaying the original address.

Example:

```text
MAC-4db90b248d02
```

instead of the original MAC address.

The current prototype contains a development/testing anonymisation key in the application configuration. For deployment outside the experimental environment, the key should be supplied securely through configuration, an environment variable, or another secret-management mechanism rather than being hard-coded.

---

## 11. Flow Reconstruction

Flows are identified using a directional five-tuple consisting of:

```text
Source IP
Destination IP
Source Port
Destination Port
Transport Protocol
```

TCP and UDP flows are therefore treated directionally.

UDP does not provide connection-establishment and termination semantics comparable to TCP. The current prototype uses an inactivity threshold to separate repeated UDP activity associated with the same five-tuple.

The current UDP inactivity threshold is:

```text
30 seconds
```

This is an implementation choice for the prototype and should not be interpreted as a protocol-defined UDP timeout.

---

## 12. Port and Application Characterisation

The framework records:

- source ports;
- destination ports;
- source/destination port pairs;
- transport protocol;
- inferred common services.

Service names are inferred from commonly associated port numbers.

For example, traffic involving UDP port 53 may be reported as DNS.

This is **port-based inference only**. A port number does not prove that a particular application generated the traffic.

---

## 13. Checksum Analysis

The framework currently analyses:

- IPv4 header checksums;
- TCP checksums;
- UDP checksums.

Results can be classified as:

```text
Present
Absent
Valid
Invalid
Unverifiable
```

Transport checksum results should be interpreted with care when analysing captures collected from live hosts because checksum offloading by network hardware or the operating system can cause captured packets to appear to contain invalid checksums even when the transmitted packet is valid.

---

## 14. Protocol Compliance

The framework implements a limited set of observable packet-level compliance checks.

The current compliance module should **not** be interpreted as a complete formal RFC conformance-testing system.

Results are classified as:

```text
Compliant
Non-compliant
Unverifiable
Not applicable
```

The results apply only to the implemented rules and to properties that can be observed from the supplied packet capture.

---

## 15. Statistical Analysis

When statistical analysis is enabled, the framework calculates descriptive statistics including:

- count;
- mean;
- median;
- standard deviation;
- minimum;
- maximum;
- 25th percentile;
- 75th percentile;
- 95th percentile;
- 99th percentile;
- coefficient of variation.

Statistics can be generated for measures such as:

- packet size;
- flow duration;
- packets per flow;
- bytes per flow;
- average packet size per flow;
- packets per second;
- bytes per second;
- average inter-arrival time.

---

## 16. Performance Measurement

The framework records performance metrics for the packet-analysis phase.

These include:

```text
Processing time
Input file size
Packets processed
Bytes processed
Packets per second
Bytes per second
Megabytes per second
Heap allocation delta
Total allocation
Flow count
```

Console rendering and output-file export are excluded from the main analysis-engine timing.

Memory values are obtained from the Go runtime and should not be interpreted as exact operating-system peak-memory measurements.

---

## 17. Reproducing Feature-Level Performance Experiments

The configurable modes can be used to compare the processing overhead associated with different characterisation features.

For example:

```powershell
go run .\cmd\protocol-characterizer .\data\benchmark.pcap baseline
go run .\cmd\protocol-characterizer .\data\benchmark.pcap checksums
go run .\cmd\protocol-characterizer .\data\benchmark.pcap ecn
go run .\cmd\protocol-characterizer .\data\benchmark.pcap compliance
go run .\cmd\protocol-characterizer .\data\benchmark.pcap flows
go run .\cmd\protocol-characterizer .\data\benchmark.pcap full
```

For more reliable timing comparisons, each configuration should be executed repeatedly rather than relying on a single run.

An example PowerShell procedure for five repetitions per configuration is:

```powershell
$modes = @(
    "baseline",
    "checksums",
    "ecn",
    "compliance",
    "flows",
    "full"
)

$runs = 5
$pcap = ".\data\benchmark.pcap"
$outputFile = ".\output\benchmark_results.csv"

$results = @()

foreach ($mode in $modes) {

    for ($run = 1; $run -le $runs; $run++) {

        Write-Host "Mode: $mode | Run: $run"

        go run .\cmd\protocol-characterizer $pcap $mode | Out-Null

        $json = Get-Content ".\output\results.json" -Raw |
            ConvertFrom-Json

        $results += [PSCustomObject]@{
            Mode                  = $json.analysis_mode
            Run                   = $run
            Packets               = $json.performance.packets_processed
            Bytes                 = $json.performance.bytes_processed
            ProcessingTimeSeconds = $json.performance.processing_time_seconds
            PacketsPerSecond      = $json.performance.packets_per_second
            MegabytesPerSecond    = $json.performance.megabytes_per_second
            HeapAllocationBytes   = $json.performance.heap_allocation_bytes
            TotalAllocationBytes  = $json.performance.total_allocation_bytes
            FlowCount             = $json.performance.flow_count
        }
    }
}

$results |
    Export-Csv $outputFile -NoTypeInformation

Write-Host "Benchmark complete."
Write-Host "Results: $outputFile"
```

The resulting experimental measurements are stored in:

```text
output/benchmark_results.csv
```

Feature-processing overhead relative to baseline can then be calculated as:

```text
Overhead (%) = ((Tf - Tb) / Tb) × 100
```

where:

- `Tb` = mean baseline processing time;
- `Tf` = mean processing time with the selected feature/configuration enabled.

---

## 18. Creating a Benchmark Capture with Wireshark

A local evaluation capture can be produced using Wireshark.

1. Open Wireshark.
2. Select the active network interface.
3. Start packet capture.
4. Generate representative network activity.
5. Stop the capture.
6. Select **File → Save As**.
7. Save the capture using standard PCAP format.
8. Place the file in the project's `data` directory.

For example:

```text
data/benchmark.pcap
```

When collecting traffic, ensure that capture activities comply with applicable privacy, security, organisational, and legal requirements. Avoid capturing sensitive third-party traffic or credentials.

---

## 19. Known Prototype Limitations

The current implementation is a research prototype and has several limitations that should be considered when interpreting results.

1. Flow keys are directional; opposite directions are represented separately.
2. TCP connections that reuse the same five-tuple over a long trace are not yet fully separated using complete connection lifecycle state.
3. UDP flow separation currently uses a fixed 30-second inactivity threshold.
4. Application/service identification is primarily port-based inference.
5. ECN field characterisation is implemented, but complete connection-level ECN negotiation analysis is limited.
6. IPv6 extension-header characterisation is not exhaustive.
7. Protocol compliance covers a defined subset of observable rules rather than complete RFC conformance.
8. Fragmentation is detected, but not every fragmentation anomaly is classified by the compliance engine.
9. Runtime memory measurements are Go runtime statistics rather than exact OS peak-memory measurements.
10. Some statistical processing currently retains observations in memory and therefore requires further optimisation for extremely large traces.
11. The current implementation should not be interpreted as demonstrating terabyte-scale scalability without additional large-trace experiments.
12. The prototype currently focuses primarily on Ethernet, IPv4/IPv6, TCP, and UDP characterisation.

These limitations provide directions for future extension of the framework.

---

## 20. Troubleshooting

### `go` is not recognised

If PowerShell reports:

```text
'go' is not recognized...
```

install Go and ensure the Go executable is available through the system `PATH`.

Then reopen PowerShell and run:

```powershell
go version
```

---

### Dependencies are missing

Run:

```powershell
go mod download
go mod tidy
```

Then rebuild:

```powershell
go build .\cmd\protocol-characterizer
```

---

### PCAP file cannot be found

Confirm that the capture exists:

```powershell
Get-ChildItem .\data\
```

Then provide the correct path:

```powershell
go run .\cmd\protocol-characterizer .\data\benchmark.pcap full
```

---

### Capture is in PCAPNG format

If necessary, open the capture in Wireshark and save/export it as standard PCAP before analysis.

---

### Output files are missing

Ensure that the `output` directory exists:

```powershell
New-Item -ItemType Directory -Force .\output
```

Then rerun the analysis.

---

## 21. Quick Start

For an existing Go installation, the complete setup can be summarised as:

```powershell
cd protocol-characterizer

go version
go mod download
go mod tidy
go fmt ./...
go build .\cmd\protocol-characterizer

go run .\cmd\protocol-characterizer .\data\benchmark.pcap full
```

View the JSON results:

```powershell
Get-Content .\output\results.json
```

View reconstructed flows:

```powershell
Import-Csv .\output\flows.csv |
    Format-Table -AutoSize
```

---

## 22. Dependency

The principal external packet-processing library used by the implementation is:

```text
github.com/google/gopacket v1.1.19
```

The authoritative dependency versions for a particular source-code release are recorded in:

```text
go.mod
go.sum
```

Use those files when reproducing the environment rather than manually selecting dependency versions.

---

## 23. Reproducibility Notes

For experimental comparisons:

- use the same PCAP for all compared configurations;
- use the same machine and Go environment;
- avoid changing source code between compared runs;
- perform multiple repetitions;
- record the selected analysis mode;
- retain the raw benchmark CSV;
- report variability rather than relying only on a single timing measurement;
- distinguish functional-validation traces from performance-evaluation traces.

This helps ensure that differences between analysis configurations are attributable as far as practicable to the enabled framework functionality rather than differences in the input trace or execution procedure.

---

## 24. License and Use

This repository contains a research prototype. Any licensing, redistribution, third-party dataset, and dependency requirements should be reviewed before public distribution.

Packet captures supplied separately may be subject to their own licensing and privacy requirements and are not automatically covered by the source-code repository's terms.
