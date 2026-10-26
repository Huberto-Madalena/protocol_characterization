package performance

import (
	"os"
	"runtime"
	"time"
)

type Snapshot struct {
	StartTime time.Time

	HeapAllocBefore  uint64
	TotalAllocBefore uint64
}

type Metrics struct {
	ProcessingTimeSeconds float64 `json:"processing_time_seconds"`

	InputFileSizeBytes int64 `json:"input_file_size_bytes"`

	PacketsProcessed int `json:"packets_processed"`

	BytesProcessed int64 `json:"bytes_processed"`

	PacketsPerSecond float64 `json:"packets_per_second"`

	BytesPerSecond float64 `json:"bytes_per_second"`

	MegabytesPerSecond float64 `json:"megabytes_per_second"`

	HeapAllocationBytes uint64 `json:"heap_allocation_bytes"`

	TotalAllocationBytes uint64 `json:"total_allocation_bytes"`

	FlowCount int `json:"flow_count"`
}

func Start() Snapshot {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	return Snapshot{
		StartTime: time.Now(),

		HeapAllocBefore: mem.HeapAlloc,

		TotalAllocBefore: mem.TotalAlloc,
	}
}

func Stop(
	start Snapshot,
	filename string,
	packetsProcessed int,
	bytesProcessed int64,
	flowCount int,
) Metrics {
	elapsed := time.Since(start.StartTime)

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	fileSize := int64(0)

	if info, err := os.Stat(filename); err == nil {
		fileSize = info.Size()
	}

	seconds := elapsed.Seconds()

	packetsPerSecond := 0.0
	bytesPerSecond := 0.0
	megabytesPerSecond := 0.0

	if seconds > 0 {
		packetsPerSecond =
			float64(packetsProcessed) / seconds

		bytesPerSecond =
			float64(bytesProcessed) / seconds

		megabytesPerSecond =
			bytesPerSecond / (1024 * 1024)
	}

	heapAllocation := uint64(0)

	if mem.HeapAlloc >= start.HeapAllocBefore {
		heapAllocation =
			mem.HeapAlloc - start.HeapAllocBefore
	}

	totalAllocation := uint64(0)

	if mem.TotalAlloc >= start.TotalAllocBefore {
		totalAllocation =
			mem.TotalAlloc - start.TotalAllocBefore
	}

	return Metrics{
		ProcessingTimeSeconds: seconds,

		InputFileSizeBytes: fileSize,

		PacketsProcessed: packetsProcessed,

		BytesProcessed: bytesProcessed,

		PacketsPerSecond: packetsPerSecond,

		BytesPerSecond: bytesPerSecond,

		MegabytesPerSecond: megabytesPerSecond,

		HeapAllocationBytes: heapAllocation,

		TotalAllocationBytes: totalAllocation,

		FlowCount: flowCount,
	}
}
