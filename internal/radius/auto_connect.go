package radius

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/noblifi/noblifi/backend/internal/vouchers"
)

type autoConnectFlight struct {
	done  chan struct{}
	state VoucherRadiusState
	err   error
}

var reusableVoucherFlights sync.Map

func (s *Service) syncReusableVoucher(
	code string,
) (VoucherRadiusState, error) {
	code = normalizeVoucherCode(code)
	if code == "" {
		return VoucherRadiusState{}, ErrVoucherUnavailable
	}

	newFlight := &autoConnectFlight{
		done: make(chan struct{}),
	}

	actual, loaded :=
		reusableVoucherFlights.LoadOrStore(
			code,
			newFlight,
		)

	if loaded {
		flight :=
			actual.(*autoConnectFlight)

		select {
		case <-flight.done:
			return flight.state, flight.err

		case <-time.After(6 * time.Second):
			return VoucherRadiusState{},
				errors.New(
					"voucher refresh is already in progress",
				)
		}
	}

	defer func() {
		close(newFlight.done)
		reusableVoucherFlights.Delete(code)
	}()

	newFlight.state,
		newFlight.err =
		s.SyncVoucher(code)

	return newFlight.state,
		newFlight.err
}

// ValidVoucherForDevice finds an already-active, unexpired voucher bound to
// this MAC and refreshes its RADIUS reply before automatic reconnect.
func (s *Service) ValidVoucherForDevice(deviceMAC string) (string, bool, error) {
	mac, err := normalizeAutoConnectMAC(deviceMAC)
	if err != nil {
		return "", false, nil
	}

	var items []vouchers.Voucher
	if err := s.db.
		Where("device_mac = ? AND LOWER(status) IN ?", mac, []string{"active", "used"}).
		Order("updated_at DESC").
		Find(&items).Error; err != nil {
		return "", false, err
	}

	now := time.Now().UTC()
	for _, voucher := range items {
		if voucher.ExpiresAt == nil || !voucher.ExpiresAt.After(now) {
			continue
		}
		state, err := s.syncReusableVoucher(voucher.Code)
		if err != nil {
			return "", false, fmt.Errorf("sync reusable voucher %s: %w", voucher.Code, err)
		}
		if normalizeVoucherStatus(state.Status) != "active" {
			continue
		}
		return voucher.Code, true, nil
	}
	return "", false, nil
}

func normalizeAutoConnectMAC(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return "", errors.New("MAC address is required")
	}
	var raw strings.Builder
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'F':
			raw.WriteRune(r)
		case r == ':' || r == '-' || r == '.' || r == ' ':
			continue
		default:
			return "", errors.New("invalid MAC address")
		}
	}
	hex := raw.String()
	if len(hex) != 12 {
		return "", errors.New("invalid MAC address")
	}
	parts := make([]string, 0, 6)
	for i := 0; i < 12; i += 2 {
		parts = append(parts, hex[i:i+2])
	}
	return strings.Join(parts, ":"), nil
}
