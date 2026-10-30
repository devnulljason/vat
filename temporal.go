package main

type Maturity int

const (
	MatNotDefined Maturity = iota
	MatUnproven
	MatProofOfConcept
	MatFunctional
	MatHigh
)

var maturityString = map[Maturity]string{
	MatNotDefined:     "Not Defined",
	MatUnproven:       "Unproven",
	MatProofOfConcept: "Proof-of-Concept",
	MatFunctional:     "Functional",
	MatHigh:           "High",
}

var maturityValue = map[Maturity]float64{
	MatUnproven:       0.91,
	MatProofOfConcept: 0.94,
	MatFunctional:     0.97,
	MatHigh:           1.0,
	MatNotDefined:     1.0,
}

func (m Maturity) String() string {
	return maturityString[m]
}

func (m Maturity) value() float64 {
	return maturityValue[m]
}

type Remediation int

const (
	RemNotDefined Remediation = iota
	RemOfficialFix
	RemTemporaryFix
	RemWorkaround
	RemUnavailable
)

var remediationString = map[Remediation]string{
	RemNotDefined:   "Not Defined",
	RemOfficialFix:  "Official Fix",
	RemTemporaryFix: "Temporary Fix",
	RemWorkaround:   "Workaround",
	RemUnavailable:  "Unavailable",
}

var remediationValue = map[Remediation]float64{
	RemOfficialFix:  0.95,
	RemTemporaryFix: 0.96,
	RemWorkaround:   0.97,
	RemUnavailable:  1.0,
	RemNotDefined:   1.0,
}

func (r Remediation) String() string {
	return remediationString[r]
}

func (r Remediation) value() float64 {
	return remediationValue[r]
}

type Confidence int

const (
	ConNotDefined Confidence = iota
	ConUnknown
	ConReasonable
	ConConfirmed
)

var confidenceString = map[Confidence]string{
	ConNotDefined: "Not Defined",
	ConUnknown:    "Unknown",
	ConReasonable: "Reasonable",
	ConConfirmed:  "Confirmed",
}

var confidenceValue = map[Confidence]float64{
	ConUnknown:    0.92,
	ConReasonable: 0.96,
	ConConfirmed:  1.0,
	ConNotDefined: 1.0,
}

func (c Confidence) String() string {
	return confidenceString[c]
}

func (c Confidence) value() float64 {
	return confidenceValue[c]
}
