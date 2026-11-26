package main

type outcome string

const (
	refused      outcome = "REFUSED"
	allowed      outcome = "ALLOWED"
	inconclusive outcome = "INCONCLUSIVE"
)

// classify requires independent state verification for a refusal. An error
// alone is not evidence that the original protected version survived.
func classify(operationSucceeded, readbackVerified bool) outcome {
	if operationSucceeded {
		return allowed
	}
	if readbackVerified {
		return refused
	}
	return inconclusive
}
