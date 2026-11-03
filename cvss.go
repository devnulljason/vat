package main

import (
	"fmt"
	"math"
	"strings"
)

type CVSS struct {
	AttackVector       vector
	AttackComplexity   complexity
	PrivilegesRequired privilege
	UserInteraction    interaction

	Scope scope

	Confidentiality impact
	Integrity       impact
	Availability    impact

	ExploitMaturity  Maturity
	RemediationLevel Remediation
	ReportConfidence Confidence

	ConfidentialityRequirement ImpactRequirement
	IntegrityRequirement       ImpactRequirement
	AvailabilityRequirement    ImpactRequirement
	ModifiedAttackVector       vector
	ModifiedAttackComplexity   complexity
	ModifiedPrivilegesRequired privilege
	ModifiedUserInteraction    interaction
	ModifiedScope              scope
	ModifiedConfidentiality    impact
	ModifiedIntegrity          impact
	ModifiedAvailability       impact
}

func (c CVSS) EnvironmentalScore() float64 {
	mCon := c.modconfidentiality()
	mInt := c.modintegrity()
	mAva := c.modavailability()

	conReq := impactRequirement(c.ConfidentialityRequirement)
	intReq := impactRequirement(c.IntegrityRequirement)
	avaReq := impactRequirement(c.AvailabilityRequirement)

	miss := 1 - ((1 - mCon*conReq) * (1 - mInt*intReq) * (1 - mAva*avaReq))
	miss = math.Min(miss, 0.915)
	if miss <= 0 {
		return 0
	}

	mAV := c.modvector()
	mAC := c.modcomplexity()
	mPR := c.modprivileges()
	mUI := c.modinteraction()

	mexp := 8.22 * mAV * mAC * mPR * mUI

	scopeChanged := c.Scope == ScopeChanged
	if c.ModifiedScope != scope(notDefined) {
		scopeChanged = c.ModifiedScope == ScopeChanged
	}

	temp := c.temporalScalar()

	if scopeChanged {
		mimp := 7.52*(miss-0.029) - 3.25*math.Pow(miss*0.9731-0.02, 13)

		return roundup(roundup(math.Min(1.08*(mimp+mexp), 10.0)) * temp)
	}

	mimp := 6.42 * miss
	return roundup(roundup(math.Min(mimp+mexp, 10)) * temp)
}

func (c CVSS) Score() float64 {
	iss := 1 - ((1 - c.confidentiality()) * (1 - c.integrity()) * (1 - c.availability()))
	if iss == 0 {
		return 0
	}

	exp := 8.22 *
		c.vector() *
		c.complexity() *
		c.privileges() *
		c.interaction()

	if c.Scope == ScopeChanged {
		imp := 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
		return roundup(math.Min(1.08*(imp+exp), 10))
	}

	imp := 6.42 * iss
	return roundup(math.Min(imp+exp, 10.0))
}

const cvss31Header = "CVSS:3.1"

func (c CVSS) String() string {
	var vec strings.Builder
	vec.WriteString(cvss31Header)

	fmt.Fprintf(&vec, "/AV:%.1s", c.AttackVector)
	fmt.Fprintf(&vec, "/AC:%.1s", c.AttackComplexity)
	fmt.Fprintf(&vec, "/PR:%.1s", c.PrivilegesRequired)
	fmt.Fprintf(&vec, "/UI:%.1s", c.UserInteraction)
	fmt.Fprintf(&vec, "/S:%.1s", c.Scope)
	fmt.Fprintf(&vec, "/C:%.1s", c.Confidentiality)
	fmt.Fprintf(&vec, "/I:%.1s", c.Integrity)
	fmt.Fprintf(&vec, "/A:%.1s", c.Availability)

	if c.ExploitMaturity != MatNotDefined {
		fmt.Fprintf(&vec, "/E:%.1s", c.ExploitMaturity)
	}
	if c.RemediationLevel != RemNotDefined {
		fmt.Fprintf(&vec, "/RL:%.1s", c.RemediationLevel)
	}
	if c.ReportConfidence != ConNotDefined {
		fmt.Fprintf(&vec, "/RC:%.1s", c.ReportConfidence)
	}

	if c.ConfidentialityRequirement != RequirementNotDefined {
		fmt.Fprintf(&vec, "/CR:%.1s", c.ConfidentialityRequirement)
	}
	if c.IntegrityRequirement != RequirementNotDefined {
		fmt.Fprintf(&vec, "/IR:%.1s", c.IntegrityRequirement)
	}
	if c.AvailabilityRequirement != RequirementNotDefined {
		fmt.Fprintf(&vec, "/AR:%.1s", c.AvailabilityRequirement)
	}
	if c.ModifiedAttackVector != vector(notDefined) {
		fmt.Fprintf(&vec, "/MAV:%.1s", c.ModifiedAttackVector)
	}
	if c.ModifiedAttackComplexity != complexity(notDefined) {
		fmt.Fprintf(&vec, "/MAC:%.1s", c.ModifiedAttackComplexity)
	}
	if c.ModifiedPrivilegesRequired != privilege(notDefined) {
		fmt.Fprintf(&vec, "/MPR:%.1s", c.ModifiedPrivilegesRequired)
	}
	if c.ModifiedUserInteraction != interaction(notDefined) {
		fmt.Fprintf(&vec, "/MUI:%.1s", c.ModifiedUserInteraction)
	}
	if c.ModifiedScope != scope(notDefined) {
		fmt.Fprintf(&vec, "/MS:%.1s", c.ModifiedScope)
	}
	if c.ModifiedConfidentiality != impact(notDefined) {
		fmt.Fprintf(&vec, "/MC:%.1s", c.ModifiedConfidentiality)
	}
	if c.ModifiedIntegrity != impact(notDefined) {
		fmt.Fprintf(&vec, "/MI:%.1s", c.ModifiedIntegrity)
	}
	if c.ModifiedAvailability != impact(notDefined) {
		fmt.Fprintf(&vec, "/MA:%.1s", c.ModifiedAvailability)
	}

	return vec.String()
}

func (c CVSS) TemporalScore() float64 {
	return roundup(c.Score() * c.temporalScalar())
}

func (c CVSS) temporalScalar() float64 {
	return c.ExploitMaturity.value() * c.RemediationLevel.value() * c.ReportConfidence.value()
}

func (c CVSS) vector() float64 {
	switch c.AttackVector {
	case VectorNetwork:
		return 0.85
	case VectorAdjacent:
		return 0.62
	case VectorLocal:
		return 0.55
	case VectorPhysical:
		return 0.2
	default:
		return 0
	}
}

func (c CVSS) modvector() float64 {
	switch c.ModifiedAttackVector {
	case vector(notDefined):
		return c.vector()
	case VectorNetwork:
		return 0.85
	case VectorAdjacent:
		return 0.62
	case VectorLocal:
		return 0.55
	case VectorPhysical:
		return 0.2
	default:
		return 0
	}
}

func (c CVSS) complexity() float64 {
	switch c.AttackComplexity {
	case ComplexityLow:
		return 0.77
	case ComplexityHigh:
		return 0.44
	default:
		return 0
	}
}

func (c CVSS) modcomplexity() float64 {
	switch c.ModifiedAttackComplexity {
	case complexity(notDefined):
		return c.complexity()
	case ComplexityLow:
		return 0.77
	case ComplexityHigh:
		return 0.44
	default:
		return 0
	}
}

func (c CVSS) privileges() float64 {
	switch c.PrivilegesRequired {
	case PrivNone:
		return 0.85
	case PrivLow:
		if c.Scope == ScopeChanged {
			return 0.68
		}
		return 0.62
	case PrivHigh:
		if c.Scope == ScopeChanged {
			return 0.5
		}
		return 0.27
	default:
		return 0
	}
}

func (c CVSS) modprivileges() float64 {
	scopeChanged := c.Scope == ScopeChanged
	if c.ModifiedScope != scope(notDefined) {
		scopeChanged = c.ModifiedScope == ScopeChanged
	}

	switch c.ModifiedPrivilegesRequired {
	case privilege(notDefined):
		return c.privileges()
	case PrivNone:
		return 0.85
	case PrivLow:
		if scopeChanged {
			return 0.68
		}
		return 0.62
	case PrivHigh:
		if scopeChanged {
			return 0.5
		}
		return 0.27
	default:
		return 0
	}
}

func (c CVSS) interaction() float64 {
	switch c.UserInteraction {
	case InteractionNone:
		return 0.85
	case InteractionRequired:
		return 0.62
	default:
		return 0
	}
}

func (c CVSS) modinteraction() float64 {
	switch c.ModifiedUserInteraction {
	case interaction(notDefined):
		return c.interaction()
	case InteractionNone:
		return 0.85
	case InteractionRequired:
		return 0.62
	default:
		return 0
	}
}

func (c CVSS) confidentiality() float64 {
	switch c.Confidentiality {
	case ImpactHigh:
		return 0.56
	case ImpactLow:
		return 0.22
	case ImpactNone:
		return 0
	default:
		return 0
	}
}

func (c CVSS) modconfidentiality() float64 {
	switch c.ModifiedConfidentiality {
	case impact(notDefined):
		return c.confidentiality()
	case ImpactHigh:
		return 0.56
	case ImpactLow:
		return 0.22
	case ImpactNone:
		return 0
	default:
		return 0
	}
}

func (c CVSS) integrity() float64 {
	switch c.Integrity {
	case ImpactHigh:
		return 0.56
	case ImpactLow:
		return 0.22
	case ImpactNone:
		return 0
	default:
		return 0
	}
}

func (c CVSS) modintegrity() float64 {
	switch c.ModifiedIntegrity {
	case impact(notDefined):
		return c.integrity()
	case ImpactHigh:
		return 0.56
	case ImpactLow:
		return 0.22
	case ImpactNone:
		return 0
	default:
		return 0
	}
}

func (c CVSS) availability() float64 {
	switch c.Availability {
	case ImpactHigh:
		return 0.56
	case ImpactLow:
		return 0.22
	case ImpactNone:
		return 0
	default:
		return 0
	}
}

func (c CVSS) modavailability() float64 {
	switch c.ModifiedAvailability {
	case impact(notDefined):
		return c.availability()
	case ImpactHigh:
		return 0.56
	case ImpactLow:
		return 0.22
	case ImpactNone:
		return 0
	default:
		return 0
	}
}

func impactRequirement(imp ImpactRequirement) float64 {
	switch imp {
	case RequirementHigh:
		return 1.5
	case RequirementMedium:
		return 1
	case RequirementLow:
		return 0.5
	case RequirementNotDefined:
		return 1
	default:
		return 0
	}
}

func roundup(x float64) float64 {
	intx := int(math.Round(x * 100_000))
	if intx%10_000 == 0 {
		return float64(intx) / 100_000
	}
	return float64(intx/10_000+1) / 10
}
