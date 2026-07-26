package plans

import (
	"testing"

	"github.com/google/uuid"
)

func TestPreparePlanForCreateAssignsIDWhenMissing(t *testing.T) {
	plan := Plan{}

	preparePlanForCreate(&plan)

	if plan.ID == uuid.Nil {
		t.Fatal("expected plan ID to be assigned")
	}
}
