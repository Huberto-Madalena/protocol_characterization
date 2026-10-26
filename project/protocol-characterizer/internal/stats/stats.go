package stats

import (
	"math"
	"sort"
)

type Summary struct {
	Count                int
	Mean                 float64
	Median               float64
	StandardDeviation    float64
	Minimum              float64
	Maximum              float64
	Percentile25         float64
	Percentile75         float64
	Percentile95         float64
	Percentile99         float64
	CoefficientVariation float64
}

func Calculate(values []float64) Summary {
	var result Summary

	if len(values) == 0 {
		return result
	}

	copied := make([]float64, len(values))
	copy(copied, values)

	sort.Float64s(copied)

	result.Count = len(copied)
	result.Minimum = copied[0]
	result.Maximum = copied[len(copied)-1]

	result.Mean = mean(copied)
	result.Median = percentile(copied, 50)
	result.StandardDeviation = standardDeviation(
		copied,
		result.Mean,
	)

	result.Percentile25 = percentile(copied, 25)
	result.Percentile75 = percentile(copied, 75)
	result.Percentile95 = percentile(copied, 95)
	result.Percentile99 = percentile(copied, 99)

	if result.Mean != 0 {
		result.CoefficientVariation =
			result.StandardDeviation / result.Mean
	}

	return result
}

func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	var total float64

	for _, value := range values {
		total += value
	}

	return total / float64(len(values))
}

func standardDeviation(
	values []float64,
	meanValue float64,
) float64 {
	if len(values) == 0 {
		return 0
	}

	var squaredDifferenceTotal float64

	for _, value := range values {
		difference := value - meanValue

		squaredDifferenceTotal +=
			difference * difference
	}

	variance :=
		squaredDifferenceTotal / float64(len(values))

	return math.Sqrt(variance)
}

func percentile(
	sortedValues []float64,
	percent float64,
) float64 {
	if len(sortedValues) == 0 {
		return 0
	}

	if len(sortedValues) == 1 {
		return sortedValues[0]
	}

	if percent <= 0 {
		return sortedValues[0]
	}

	if percent >= 100 {
		return sortedValues[len(sortedValues)-1]
	}

	position :=
		(percent / 100) *
			float64(len(sortedValues)-1)

	lowerIndex := int(math.Floor(position))
	upperIndex := int(math.Ceil(position))

	if lowerIndex == upperIndex {
		return sortedValues[lowerIndex]
	}

	lowerValue := sortedValues[lowerIndex]
	upperValue := sortedValues[upperIndex]

	fraction :=
		position - float64(lowerIndex)

	return lowerValue +
		fraction*(upperValue-lowerValue)
}
