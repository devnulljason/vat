package main

type Vector int

const (
	VectorPhysical Vector = iota
	VectorLocal
	VectorAdjacent
	VectorNetwork
)

var vectorString = map[Vector]string{
	VectorPhysical: "Physical",
	VectorLocal:    "Local",
	VectorAdjacent: "Adjacent",
	VectorNetwork:  "Network",
}

var vectorValue = map[Vector]float64{
	VectorPhysical: 0.2,
	VectorLocal:    0.55,
	VectorAdjacent: 0.62,
	VectorNetwork:  0.85,
}

func (v Vector) String() string {
	return vectorString[v]
}

func (v Vector) value() float64 {
	return vectorValue[v]
}

type Complexity int

const (
	ComplexityHigh Complexity = iota
	ComplexityLow
)

var complexityString = map[Complexity]string{
	ComplexityHigh: "High",
	ComplexityLow:  "Low",
}

var complexityValue = map[Complexity]float64{
	ComplexityHigh: 0.44,
	ComplexityLow:  0.77,
}

func (c Complexity) String() string {
	return complexityString[c]
}

func (c Complexity) value() float64 {
	return complexityValue[c]
}

type Privilege int

const (
	PrivHigh Privilege = iota
	PrivLow
	PrivNone
)

var privString = map[Privilege]string{
	PrivHigh: "High",
	PrivLow:  "Low",
	PrivNone: "None",
}

func (p Privilege) String() string {
	return privString[p]
}

func (p Privilege) value(s Scope) float64 {
	if p == PrivNone {
		return 0.85
	}

	if p == PrivLow {
		if s == ScopeChanged {
			return 0.68
		}
		return 0.62
	}

	if s == ScopeChanged {
		return 0.5
	}
	return 0.27
}

type Interaction int

const (
	InteractionRequired Interaction = iota
	InteractionNone
)

var interactionString = map[Interaction]string{
	InteractionRequired: "Required",
	InteractionNone:     "None",
}

var interactionValue = map[Interaction]float64{
	InteractionRequired: 0.62,
	InteractionNone:     0.85,
}

func (i Interaction) String() string {
	return interactionString[i]
}

func (i Interaction) value() float64 {
	return interactionValue[i]
}

type Scope int

const (
	ScopeUnchanged Scope = iota
	ScopeChanged
)

var scopeString = map[Scope]string{
	ScopeUnchanged: "Unchanged",
	ScopeChanged:   "Changed",
}

func (s Scope) String() string {
	return scopeString[s]
}

type Impact int

const (
	ImpactNone Impact = iota
	ImpactLow
	ImpactHigh
)

var impactString = map[Impact]string{
	ImpactNone: "None",
	ImpactLow:  "Low",
	ImpactHigh: "High",
}

var impactValue = map[Impact]float64{
	ImpactNone: 0,
	ImpactLow:  0.22,
	ImpactHigh: 0.56,
}

func (i Impact) String() string {
	return impactString[i]
}

func (i Impact) value() float64 {
	return impactValue[i]
}
