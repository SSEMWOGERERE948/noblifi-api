package plans

import "testing"

func TestDurationToMinutes(t *testing.T) {
	tests := []struct {
		value int
		unit  string
		want  int
	}{
		{30, DurationUnitMinutes, 30},
		{2, DurationUnitHours, 120},
		{1, DurationUnitWeeks, 10080},
		{1, DurationUnitMonths, 43200},
	}

	for _, test := range tests {
		got, err := durationToMinutes(test.value, test.unit)
		if err != nil {
			t.Fatalf(
				"durationToMinutes(%d, %q) returned error: %v",
				test.value,
				test.unit,
				err,
			)
		}

		if got != test.want {
			t.Fatalf(
				"durationToMinutes(%d, %q) = %d, want %d",
				test.value,
				test.unit,
				got,
				test.want,
			)
		}
	}
}

func TestNewDurationAPI(t *testing.T) {
	plan := Plan{
		Name:          "2 Hour WiFi",
		Price:         1000,
		DurationValue: 2,
		DurationUnit:  "hours",
		MaxDevices:    1,
	}

	if err := normalizePlanForCreate(&plan); err != nil {
		t.Fatalf("normalizePlanForCreate returned error: %v", err)
	}

	if plan.DurationMinutes != 120 {
		t.Fatalf(
			"DurationMinutes = %d, want 120",
			plan.DurationMinutes,
		)
	}
}

func TestLegacyDurationMinutes(t *testing.T) {
	plan := Plan{
		Name:            "Weekly",
		Price:           5000,
		DurationMinutes: 10080,
		MaxDevices:      1,
	}

	if err := normalizePlanForCreate(&plan); err != nil {
		t.Fatalf("normalizePlanForCreate returned error: %v", err)
	}

	if plan.DurationValue != 1 {
		t.Fatalf(
			"DurationValue = %d, want 1",
			plan.DurationValue,
		)
	}

	if plan.DurationUnit != DurationUnitWeeks {
		t.Fatalf(
			"DurationUnit = %q, want %q",
			plan.DurationUnit,
			DurationUnitWeeks,
		)
	}
}

func TestZeroDataLimitMeansUnlimited(t *testing.T) {
	zero := 0

	plan := Plan{
		Name:            "Unlimited Data",
		Price:           1000,
		DurationMinutes: 60,
		DataLimitMB:     &zero,
		MaxDevices:      1,
	}

	if err := normalizePlanForCreate(&plan); err != nil {
		t.Fatalf("normalizePlanForCreate returned error: %v", err)
	}

	if plan.DataLimitMB != nil {
		t.Fatalf(
			"DataLimitMB = %v, want nil",
			plan.DataLimitMB,
		)
	}
}