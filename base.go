package main

type metric int

const (
	notDefined metric = iota

	network
	adjacent
	local
	physical

	high
	low
	none

	required

	unchanged
	changed
)

var metricString = map[metric]string{
	notDefined: "Not Defined",

	network:  "Network",
	adjacent: "Adjacent",
	local:    "Local",
	physical: "Physical",

	high: "High",
	low:  "Low",
	none: "None",

	required: "Required",

	unchanged: "Unchanged",
	changed:   "Changed",
}

func (m metric) String() string {
	return metricString[m]
}

type vector metric

const (
	VectorNetwork  = vector(network)
	VectorAdjacent = vector(adjacent)
	VectorLocal    = vector(local)
	VectorPhysical = vector(physical)
)

func (v vector) String() string {
	return metric(v).String()
}

type complexity metric

const (
	ComplexityLow  = complexity(low)
	ComplexityHigh = complexity(high)
)

func (c complexity) String() string {
	return metric(c).String()
}

type privilege metric

const (
	PrivHigh = privilege(high)
	PrivLow  = privilege(low)
	PrivNone = privilege(none)
)

func (p privilege) String() string {
	return metric(p).String()
}

type interaction metric

const (
	InteractionRequired = interaction(required)
	InteractionNone     = interaction(none)
)

func (i interaction) String() string {
	return metric(i).String()
}

type scope metric

const (
	ScopeUnchanged = scope(unchanged)
	ScopeChanged   = scope(changed)
)

func (s scope) String() string {
	return metric(s).String()
}

type impact metric

const (
	ImpactNone = impact(none)
	ImpactLow  = impact(low)
	ImpactHigh = impact(high)
)

func (i impact) String() string {
	return metric(i).String()
}
