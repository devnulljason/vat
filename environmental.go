package main

type ImpactRequirement int

const (
	ImpReqNotDefined ImpactRequirement = iota
	ImpReqLow
	ImpReqMedium
	ImpReqHigh
)

var impactReqString = map[ImpactRequirement]string{
	ImpReqNotDefined: "Not Defined",
	ImpReqLow:        "Low",
	ImpReqMedium:     "Medium",
	ImpReqHigh:       "High",
}

func (i ImpactRequirement) String() string {
	return impactReqString[i]
}

type ModifiedVector int

const (
	ModVecNotDefined ModifiedVector = iota
	ModVecPhysical
	ModVecLocal
	ModVecAdjacent
	ModVecNetwork
)

var modifiedVectorString = map[ModifiedVector]string{
	ModVecNotDefined: "Not Defined",
	ModVecPhysical:   "Physical",
	ModVecLocal:      "Local",
	ModVecAdjacent:   "Adjacent",
	ModVecNetwork:    "Network",
}

func (v ModifiedVector) String() string {
	return modifiedVectorString[v]
}

type ModifiedComplexity int

const (
	ModCompNotDefined ModifiedComplexity = iota
	ModCompHigh
	ModCompLow
)

var modCompString = map[ModifiedComplexity]string{
	ModCompNotDefined: "Not Defined",
	ModCompHigh:       "High",
	ModCompLow:        "Low",
}

func (c ModifiedComplexity) String() string {
	return modCompString[c]
}

type ModifiedPrivilege int

const (
	ModPrivNotDefined ModifiedPrivilege = iota
	ModPrivHigh
	ModPrivLow
	ModPrivNone
)

var modPrivString = map[ModifiedPrivilege]string{
	ModPrivNotDefined: "Not Defined",
	ModPrivHigh:       "High",
	ModPrivLow:        "Low",
	ModPrivNone:       "None",
}

func (p ModifiedPrivilege) String() string {
	return modPrivString[p]
}

type ModifiedInteraction int

const (
	ModIntNotDefined ModifiedInteraction = iota
	ModIntRequired
	ModIntNone
)

var modIntString = map[ModifiedInteraction]string{
	ModIntNotDefined: "Not Defined",
	ModIntRequired:   "Required",
	ModIntNone:       "None",
}

func (i ModifiedInteraction) String() string {
	return modIntString[i]
}

type ModifiedScope int

const (
	ModScopeNotDefined ModifiedScope = iota
	ModScopeUnchanged
	ModScopeChanged
)

var modScopeString = map[ModifiedScope]string{
	ModScopeNotDefined: "Not Defined",
	ModScopeUnchanged:  "Unchanged",
	ModScopeChanged:    "Changed",
}

func (s ModifiedScope) String() string {
	return modScopeString[s]
}

type ModifiedImpact int

const (
	ModImpactNotDefined ModifiedImpact = iota
	ModImpactNone
	ModImpactLow
	ModImpactHigh
)

var modImpactString = map[ModifiedImpact]string{
	ModImpactNotDefined: "Not Defined",
	ModImpactNone:       "None",
	ModImpactLow:        "Low",
	ModImpactHigh:       "High",
}

func (i ModifiedImpact) String() string {
	return modImpactString[i]
}
