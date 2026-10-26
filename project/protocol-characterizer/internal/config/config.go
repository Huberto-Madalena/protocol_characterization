package config

type AnalysisConfig struct {
	Name string

	TCPFlags   bool
	TCPOptions bool
	ECN        bool
	Checksums  bool
	Ports      bool
	IP         bool
	Compliance bool
	Flows      bool
	Statistics bool
}

func Baseline() AnalysisConfig {
	return AnalysisConfig{
		Name: "baseline",
	}
}

func Checksums() AnalysisConfig {
	return AnalysisConfig{
		Name:      "checksums",
		Checksums: true,
	}
}

func ECN() AnalysisConfig {
	return AnalysisConfig{
		Name: "ecn",
		ECN:  true,
	}
}

func Compliance() AnalysisConfig {
	return AnalysisConfig{
		Name:       "compliance",
		Checksums:  true,
		Compliance: true,
	}
}

func Flows() AnalysisConfig {
	return AnalysisConfig{
		Name:       "flows",
		Flows:      true,
		Statistics: true,
	}
}

func Full() AnalysisConfig {
	return AnalysisConfig{
		Name:       "full",
		TCPFlags:   true,
		TCPOptions: true,
		ECN:        true,
		Checksums:  true,
		Ports:      true,
		IP:         true,
		Compliance: true,
		Flows:      true,
		Statistics: true,
	}
}

func FromName(name string) (AnalysisConfig, bool) {
	switch name {
	case "baseline":
		return Baseline(), true

	case "checksums":
		return Checksums(), true

	case "ecn":
		return ECN(), true

	case "compliance":
		return Compliance(), true

	case "flows":
		return Flows(), true

	case "full":
		return Full(), true

	default:
		return AnalysisConfig{}, false
	}
}
