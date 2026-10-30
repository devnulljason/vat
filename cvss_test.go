package main

import (
	"testing"
)

func TestString(t *testing.T) {
	tests := []struct {
		name string
		vuln CVSS
		want string
	}{
		{
			name: "base metrics",
			vuln: CVSS{
				AttackVector:       VectorNetwork,
				AttackComplexity:   ComplexityLow,
				PrivilegesRequired: PrivLow,
				UserInteraction:    InteractionNone,
				Scope:              ScopeChanged,
				Confidentiality:    ImpactLow,
				Integrity:          ImpactLow,
				Availability:       ImpactNone,
			},
			want: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
		},
		{
			name: "temporal metrics",
			vuln: CVSS{
				AttackVector:       VectorNetwork,
				AttackComplexity:   ComplexityHigh,
				PrivilegesRequired: PrivNone,
				UserInteraction:    InteractionNone,
				Scope:              ScopeUnchanged,
				Confidentiality:    ImpactHigh,
				Integrity:          ImpactLow,
				Availability:       ImpactNone,

				ExploitMaturity:  MatProofOfConcept,
				RemediationLevel: RemWorkaround,
				ReportConfidence: ConReasonable,
			},
			want: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N/E:P/RL:W/RC:R",
		},
		{
			name: "environmental metrics",
			vuln: CVSS{
				AttackVector:       VectorNetwork,
				AttackComplexity:   ComplexityLow,
				PrivilegesRequired: PrivNone,
				UserInteraction:    InteractionNone,
				Scope:              ScopeUnchanged,
				Confidentiality:    ImpactHigh,
				Integrity:          ImpactHigh,
				Availability:       ImpactHigh,

				ConfidentialityRequirement: ImpReqHigh,
				IntegrityRequirement:       ImpReqHigh,
				AvailabilityRequirement:    ImpReqHigh,
				ModifiedAttackVector:       ModVecAdjacent,
				ModifiedAttackComplexity:   ModCompHigh,
				ModifiedPrivilegesRequired: ModPrivLow,
				ModifiedUserInteraction:    ModIntRequired,
				ModifiedScope:              ModScopeChanged,
				ModifiedConfidentiality:    ModImpactHigh,
				ModifiedIntegrity:          ModImpactHigh,
				ModifiedAvailability:       ModImpactHigh,
			},
			want: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:C/MC:H/MI:H/MA:H",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.vuln.String()

			if got != tt.want {
				t.Errorf("want %q but got %q", tt.want, got)
			}
		})
	}
}

func TestScore(t *testing.T) {
	t.Run("base score", func(t *testing.T) {
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
	})

	t.Run("temporal score", func(t *testing.T) {
		vuln := CVSS{
			AttackVector:       VectorNetwork,
			AttackComplexity:   ComplexityHigh,
			PrivilegesRequired: PrivNone,
			UserInteraction:    InteractionNone,
			Scope:              ScopeUnchanged,
			Confidentiality:    ImpactHigh,
			Integrity:          ImpactLow,
			Availability:       ImpactNone,
			ExploitMaturity:    MatProofOfConcept,
			RemediationLevel:   RemWorkaround,
			ReportConfidence:   ConReasonable,
		}
		want := 5.7
		got := vuln.TemporalScore()

		if got != want {
			t.Errorf("want %g but got %g", want, got)
		}
	})

	t.Run("environmental score", func(t *testing.T) {
		vuln := CVSS{
			AttackVector:       VectorNetwork,
			AttackComplexity:   ComplexityLow,
			PrivilegesRequired: PrivNone,
			UserInteraction:    InteractionNone,
			Scope:              ScopeUnchanged,
			Confidentiality:    ImpactHigh,
			Integrity:          ImpactHigh,
			Availability:       ImpactHigh,

			ConfidentialityRequirement: ImpReqHigh,
			IntegrityRequirement:       ImpReqHigh,
			AvailabilityRequirement:    ImpReqHigh,
			ModifiedAttackVector:       ModVecAdjacent,
			ModifiedAttackComplexity:   ModCompHigh,
			ModifiedPrivilegesRequired: ModPrivLow,
			ModifiedUserInteraction:    ModIntRequired,
			ModifiedScope:              ModScopeChanged,
			ModifiedConfidentiality:    ModImpactHigh,
			ModifiedIntegrity:          ModImpactHigh,
			ModifiedAvailability:       ModImpactHigh,
		}
		want := 7.7
		got := vuln.EnvironmentalScore()

		if got != want {
			t.Errorf("want %g but got %g", want, got)
		}
	})
}
