package evidence

import "context"

// GovernedPlan is a server-created route. Build returns the exact bytes that
// will be sealed; Invoke must use them without re-encoding or substitution.
// Reserve durably claims budget and Arm commits the no-redispatch barrier.
// CheckRoute revalidates policy without selecting a new destination.
type GovernedPlan struct {
	Destination   Destination
	PolicyVersion string
	RegistryModel string
	Build         func(Request) ([]byte, error)
	Reserve       func(context.Context, string, []byte) (int, error)
	Arm           func(context.Context, string) error
	CheckRoute    func(context.Context) error
	Invoke        ModelFunc
}

// Governance is the server-owned planning boundary, invoked for new turns
// only. A replay must not consult a model registry, spend budget or dispatch.
type Governance func(context.Context, Request) (GovernedPlan, error)

func (p GovernedPlan) configured() bool {
	return p.Build != nil && p.Reserve != nil && p.Arm != nil && p.CheckRoute != nil && p.Invoke != nil && p.PolicyVersion != ""
}
