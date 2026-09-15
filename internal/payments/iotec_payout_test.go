package payments

import "testing"

func TestNormalizeIotecPayoutStatus(
	t *testing.T,
) {
	tests := []struct {
		input string
		want  string
	}{
		{"Success", "paid"},
		{"Pending", "processing"},
		{"SentToVendor", "processing"},
		{"AwaitingApproval", "processing"},
		{"Scheduled", "processing"},
		{"Failed", "failed"},
		{"RolledBack", "failed"},
		{"Cancelled", "failed"},
		{"Canceled", "failed"},
		{"Rejected", "failed"},
		{"SomethingNew", "processing"},
	}

	for _, test := range tests {
		got :=
			normalizeIotecPayoutStatus(
				test.input,
			)

		if got != test.want {
			t.Fatalf(
				"%q: got %q want %q",
				test.input,
				got,
				test.want,
			)
		}
	}
}

func TestIotecPayeeNameVerified(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"Fetched", true},
		{"Matched", true},
		{"Pending", false},
		{"NotMatched", false},
		{"NotFound", false},
		{"Failed", false},
		{"Barred", false},
	}

	for _, test := range tests {
		got := iotecPayeeNameVerified(test.input)
		if got != test.want {
			t.Fatalf("%q: got %v want %v", test.input, got, test.want)
		}
	}
}

func TestPayoutResultDoesNotUsePayeeUploadNameAsVerifiedIdentity(t *testing.T) {
	result := payoutResultFromIotec(iotecDisbursementResponse{
		ID:              "provider-1",
		Status:          "SentToVendor",
		ExternalID:      "merchant-1",
		Payee:           "256757251514",
		PayeeUploadName: "Uploaded Name",
		PayeeNameStatus: "Pending",
	}, "", "")

	if result.PayeeName != "" {
		t.Fatalf("PayeeName = %q, want empty when ioTec payeeName is absent", result.PayeeName)
	}
	if result.PayeeNameStatus != "Pending" {
		t.Fatalf("PayeeNameStatus = %q, want Pending", result.PayeeNameStatus)
	}
}

func TestNormalizeUgandaMSISDN(
	t *testing.T,
) {
	tests := []struct {
		input string
		want  string
	}{
		{
			"0772123456",
			"256772123456",
		},
		{
			"772123456",
			"256772123456",
		},
		{
			"+256772123456",
			"256772123456",
		},
		{
			"256772123456",
			"256772123456",
		},
	}

	for _, test := range tests {
		got, err :=
			normalizeUgandaMSISDN(
				test.input,
			)

		if err != nil {
			t.Fatalf(
				"%q: %v",
				test.input,
				err,
			)
		}

		if got != test.want {
			t.Fatalf(
				"%q: got %q want %q",
				test.input,
				got,
				test.want,
			)
		}
	}
}
