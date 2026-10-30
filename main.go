package main

import (
	"fmt"
)

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
