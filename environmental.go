package main

type ImpactRequirement int

const (
	RequirementNotDefined ImpactRequirement = iota
	RequirementLow
	RequirementMedium
	RequirementHigh
)

var impactReqString = map[ImpactRequirement]string{
	RequirementNotDefined: "Not Defined",
	RequirementLow:        "Low",
	RequirementMedium:     "Medium",
	RequirementHigh:       "High",
}

func (i ImpactRequirement) String() string {
	return impactReqString[i]
}
