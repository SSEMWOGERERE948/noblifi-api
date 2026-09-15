package vouchers

import (
	"testing"

	"github.com/google/uuid"
)

func TestVoucherServiceRequiresAuthenticatedTenant(t *testing.T) {
	service := NewService(nil)

	if _, err := service.List(nil, false); err == nil {
		t.Fatal("normal voucher list without user did not fail closed")
	}

	if _, err := service.GeneratePhysical(GenerateInput{PlanID: uuid.New(), Quantity: 1}, nil, false); err == nil {
		t.Fatal("normal voucher generation without user did not fail closed")
	}

	if err := service.Delete(uuid.New(), nil, false); err == nil {
		t.Fatal("normal voucher delete without user did not fail closed")
	}
}
