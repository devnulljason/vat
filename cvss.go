package main

import (
	"fmt"
	"math"
	"strings"
)

type CVSS struct {
	AttackVector       Vector
	AttackComplexity   Complexity
	PrivilegesRequired Privilege
	UserInteraction    Interaction

	Scope Scope

	Confidentiality Impact
	Integrity       Impact
	Availability    Impact

	ExploitMaturity  Maturity
	RemediationLevel Remediation
	ReportConfidence Confidence

	ConfidentialityRequirement ImpactRequirement
	IntegrityRequirement       ImpactRequirement
	AvailabilityRequirement    ImpactRequirement
	ModifiedAttackVector       ModifiedVector
	ModifiedAttackComplexity   ModifiedComplexity
	ModifiedPrivilegesRequired ModifiedPrivilege
	ModifiedUserInteraction    ModifiedInteraction
	ModifiedScope              ModifiedScope
	ModifiedConfidentiality    ModifiedImpact
	ModifiedIntegrity          ModifiedImpact
	ModifiedAvailability       ModifiedImpact
}

func (c CVSS) EnvironmentalScore() float64 {
	return c.Score()
}

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

	if c.ConfidentialityRequirement != ImpReqNotDefined {
		fmt.Fprintf(&vec, "/CR:%.1s", c.ConfidentialityRequirement)
	}
	if c.IntegrityRequirement != ImpReqNotDefined {
		fmt.Fprintf(&vec, "/IR:%.1s", c.IntegrityRequirement)
	}
	if c.AvailabilityRequirement != ImpReqNotDefined {
		fmt.Fprintf(&vec, "/AR:%.1s", c.AvailabilityRequirement)
	}
	if c.ModifiedAttackVector != ModVecNotDefined {
		fmt.Fprintf(&vec, "/MAV:%.1s", c.ModifiedAttackVector)
	}
	if c.ModifiedAttackComplexity != ModCompNotDefined {
		fmt.Fprintf(&vec, "/MAC:%.1s", c.ModifiedAttackComplexity)
	}
	if c.ModifiedPrivilegesRequired != ModPrivNotDefined {
		fmt.Fprintf(&vec, "/MPR:%.1s", c.ModifiedPrivilegesRequired)
	}
	if c.ModifiedUserInteraction != ModIntNotDefined {
		fmt.Fprintf(&vec, "/MUI:%.1s", c.ModifiedUserInteraction)
	}
	if c.ModifiedScope != ModScopeNotDefined {
		fmt.Fprintf(&vec, "/MS:%.1s", c.ModifiedScope)
	}
	if c.ModifiedConfidentiality != ModImpactNotDefined {
		fmt.Fprintf(&vec, "/MC:%.1s", c.ModifiedConfidentiality)
	}
	if c.ModifiedIntegrity != ModImpactNotDefined {
		fmt.Fprintf(&vec, "/MI:%.1s", c.ModifiedIntegrity)
	}
	if c.ModifiedAvailability != ModImpactNotDefined {
		fmt.Fprintf(&vec, "/MA:%.1s", c.ModifiedAvailability)
	}

	return vec.String()
}

func (c CVSS) TemporalScore() float64 {
	base := c.Score()
	exp := c.ExploitMaturity.value()
	rem := c.RemediationLevel.value()
	con := c.ReportConfidence.value()

	return roundup(base * exp * rem * con)
}

func roundup(x float64) float64 {
	intx := int(math.Round(x * 100_000))
	if intx%10_000 == 0 {
		return float64(intx) / 100_000
	}
	return float64(intx/10_000+1) / 10
}
