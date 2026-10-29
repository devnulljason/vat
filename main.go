package main

import (
	"fmt"
	"math"
	"strings"
)

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

type CVSS struct {
	AttackVector       Vector
	AttackComplexity   Complexity
	PrivilegesRequired Privilege
	UserInteraction    Interaction

	Scope Scope

	Confidentiality Impact
	Integrity       Impact
	Availability    Impact
}

const cvss3_1Header = "CVSS:3.1"

func (c CVSS) Score() float64 {
	iss := 1 - ((1 - c.Confidentiality.value()) * (1 - c.Integrity.value()) * (1 - c.Availability.value()))
	if iss == 0 {
		return 0
	}

	exp := 8.22 *
		c.AttackVector.value() *
		c.AttackComplexity.value() *
		c.PrivilegesRequired.value(c.Scope) *
		c.UserInteraction.value()

	if c.Scope == ScopeChanged {
		imp := 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
		return roundup(math.Min(1.08*(imp+exp), 10))
	}

	imp := 6.42 * iss
	return roundup(math.Min(imp+exp, 10.0))
}

func (c CVSS) String() string {
	var vec strings.Builder
	vec.WriteString(cvss3_1Header)

	fmt.Fprintf(&vec, "/AV:%.1s", c.AttackVector)
	fmt.Fprintf(&vec, "/AC:%.1s", c.AttackComplexity)
	fmt.Fprintf(&vec, "/PR:%.1s", c.PrivilegesRequired)
	fmt.Fprintf(&vec, "/UI:%.1s", c.UserInteraction)
	fmt.Fprintf(&vec, "/S:%.1s", c.Scope)
	fmt.Fprintf(&vec, "/C:%.1s", c.Confidentiality)
	fmt.Fprintf(&vec, "/I:%.1s", c.Integrity)
	fmt.Fprintf(&vec, "/A:%.1s", c.Availability)

	return vec.String()
}

func roundup(x float64) float64 {
	intx := int(math.Round(x * 100_000))
	if intx%10_000 == 0 {
		return float64(intx) / 100_000
	}
	return float64(intx/10_000+1) / 10
}

func main() {
	vuln := CVSS{
		AttackVector:       VectorNetwork,
		AttackComplexity:   ComplexityLow,
		PrivilegesRequired: PrivLow,
		UserInteraction:    InteractionNone,
		Scope:              ScopeChanged,
		Confidentiality:    ImpactLow,
		Integrity:          ImpactLow,
		Availability:       ImpactNone,
	}

	fmt.Printf("%s %2g\n", vuln, vuln.Score())
}
