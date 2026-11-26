package main

import (
	"errors"
	"testing"

	"github.com/aws/smithy-go"
)

func TestMutationResponsesOnlyCountKnownProviderDenials(t *testing.T) {
	if !expectedGuardRefusal(&smithy.GenericAPIError{Code: "AccessDenied"}) {
		t.Fatal("expected AccessDenied to classify as guard refusal")
	}
	if !expectedGuardRefusal(&smithy.GenericAPIError{Code: "InvalidRequest"}) {
		t.Fatal("expected valid Object Lock InvalidRequest refusal")
	}
	if expectedGuardRefusal(errors.New("timeout")) {
		t.Fatal("transport error must not classify as refusal")
	}
	if !expectedConditionalRejection(&smithy.GenericAPIError{Code: "PreconditionFailed"}) {
		t.Fatal("expected precondition failure")
	}
	if expectedConditionalRejection(errors.New("timeout")) {
		t.Fatal("transport error must not count as a race loser")
	}
}
