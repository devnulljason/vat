package main

import (
	"testing"
)

func TestString(t *testing.T) {
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
	want := "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"
	got := vuln.String()

	if got != want {
		t.Errorf("want %q but got %q", want, got)
	}
}

func TestScore(t *testing.T) {
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
	want := 6.4
	got := vuln.Score()

	if got != want {
		t.Errorf("want %g but got %g", want, got)
	}
}
