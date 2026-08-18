package vouchers

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/google/uuid"
)

const (
	ChannelMobileMoneyOnline = "mobile_money_online"
	ChannelPhysical          = "physical"

	MaxVoucherBatchSize   = 500
	DefaultOnlinePoolSize = 500

	MinVoucherCodeLength     = 4
	MaxVoucherCodeLength     = 9
	DefaultVoucherCodeLength = 8

	PatternAlphanumeric = "alphanumeric"
	PatternAlphabetic   = "alphabetic"
	PatternNumeric      = "numeric"
)

var (
	templates = map[string]bool{
		"compact":      true,
		"receipt":      true,
		"scratch_card": true,
	}

	patterns = map[string]bool{
		PatternAlphanumeric: true,
		PatternAlphabetic:   true,
		PatternNumeric:      true,
	}
)

type Service struct {
	repo   *Repository
	radius RadiusSyncer
}

func NewService(repo *Repository) *Service {
	return &Service{
		repo: repo,
	}
}

type RadiusSyncer interface {
	SyncVoucherForVoucher(code string) error
}

func (s *Service) SetRadiusSyncer(
	syncer RadiusSyncer,
) {
	s.radius = syncer
}

type GenerateInput struct {
	PlanID uuid.UUID

	Quantity int
	Channel  string

	Template string

	/*
		Supported values:

		alphanumeric
		alphabetic
		numeric
	*/
	Pattern string

	/*
		Number of characters in the generated voucher.

		Minimum: 4
		Maximum: 9
		Default: 8
	*/
	CodeLength int
}

/*
	Generate creates physical vouchers using the standard
	default settings.
*/
func (s *Service) Generate(
	planID uuid.UUID,
	quantity int,
	userID *uuid.UUID,
	isSuperadmin bool,
) ([]Voucher, error) {
	return s.GeneratePhysical(
		GenerateInput{
			PlanID:     planID,
			Quantity:   quantity,
			Template:   "compact",
			Pattern:    PatternAlphanumeric,
			CodeLength: DefaultVoucherCodeLength,
		},
		userID,
		isSuperadmin,
	)
}

/*
	GenerateOnlineVouchers creates the voucher pool used
	by online/mobile-money packages.

	Online vouchers use the default secure 8-character
	alphanumeric format.
*/
func (s *Service) GenerateOnlineVouchers(
	planID uuid.UUID,
	userID *uuid.UUID,
	isSuperadmin bool,
) ([]Voucher, error) {
	return s.generate(
		GenerateInput{
			PlanID:     planID,
			Quantity:   DefaultOnlinePoolSize,
			Channel:    ChannelMobileMoneyOnline,
			Pattern:    PatternAlphanumeric,
			CodeLength: DefaultVoucherCodeLength,
		},
		userID,
		isSuperadmin,
	)
}

func (s *Service) GenerateOnlineVoucherCount(
	planID uuid.UUID,
	userID *uuid.UUID,
	isSuperadmin bool,
) (int, error) {
	items, err := s.GenerateOnlineVouchers(
		planID,
		userID,
		isSuperadmin,
	)

	return len(items), err
}

/*
	GeneratePhysical validates the printable voucher
	configuration before generating the batch.
*/
func (s *Service) GeneratePhysical(
	input GenerateInput,
	userID *uuid.UUID,
	isSuperadmin bool,
) ([]Voucher, error) {
	if strings.TrimSpace(input.Template) == "" {
		input.Template = "compact"
	}

	if !templates[input.Template] {
		return nil, fmt.Errorf(
			"unknown physical voucher template: %s",
			input.Template,
		)
	}

	if strings.TrimSpace(input.Pattern) == "" {
		input.Pattern = PatternAlphanumeric
	}

	input.Pattern = strings.ToLower(
		strings.TrimSpace(input.Pattern),
	)

	if !patterns[input.Pattern] {
		return nil, fmt.Errorf(
			"unknown voucher code character type: %s",
			input.Pattern,
		)
	}

	codeLength, err := normalizeCodeLength(
		input.CodeLength,
	)

	if err != nil {
		return nil, err
	}

	input.CodeLength = codeLength
	input.Channel = ChannelPhysical

	return s.generate(
		input,
		userID,
		isSuperadmin,
	)
}

/*
	generate creates the actual voucher records.
*/
func (s *Service) generate(
	input GenerateInput,
	userID *uuid.UUID,
	isSuperadmin bool,
) ([]Voucher, error) {
	quantity := input.Quantity

	if quantity < 1 {
		quantity = 1
	}

	if quantity > MaxVoucherBatchSize {
		quantity = MaxVoucherBatchSize
	}

	channel := strings.TrimSpace(input.Channel)

	if channel == "" {
		channel = ChannelPhysical
	}

	pattern := strings.ToLower(
		strings.TrimSpace(input.Pattern),
	)

	if pattern == "" {
		pattern = PatternAlphanumeric
	}

	if !patterns[pattern] {
		return nil, fmt.Errorf(
			"unknown voucher code character type: %s",
			pattern,
		)
	}

	codeLength, err := normalizeCodeLength(
		input.CodeLength,
	)

	if err != nil {
		return nil, err
	}

	batchToken, err := randomString(
		"0123456789ABCDEF",
		10,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"generate voucher batch id: %w",
			err,
		)
	}

	batchID := fmt.Sprintf(
		"VCH-%s",
		batchToken,
	)

	items := make(
		[]Voucher,
		0,
		quantity,
	)

	/*
		Track codes already generated in this batch.

		This prevents duplicate codes inside the same
		request before they reach PostgreSQL.
	*/
	batchCodes := make(
		map[string]struct{},
		quantity,
	)

	for i := 0; i < quantity; i++ {
		voucherCode, err :=
			s.generateUniqueCode(
				pattern,
				codeLength,
				batchCodes,
			)

		if err != nil {
			return items, err
		}

		item := Voucher{
			PlanID: input.PlanID,

			Code: voucherCode,

			Channel: channel,

			BatchID: &batchID,

			Pattern: &pattern,

			Status: "unused",
		}

		if !isSuperadmin && userID != nil {
			item.UserID = userID
		}

		if channel == ChannelPhysical {
			template := input.Template
			item.Template = &template
		}

		items = append(
			items,
			item,
		)
	}

	if err := s.repo.CreateMany(items); err != nil {
		return items, err
	}

	/*
		Synchronize successfully created vouchers with
		the RADIUS subsystem.
	*/
	if s.radius != nil {
		for _, item := range items {
			if err :=
				s.radius.SyncVoucherForVoucher(
					item.Code,
				); err != nil {
				return items, err
			}
		}
	}

	return items, nil
}

/*
	generateUniqueCode creates a code that:

	1. follows the selected character type;
	2. has exactly the selected length;
	3. is not duplicated in the current batch;
	4. does not already exist in the database.
*/
func (s *Service) generateUniqueCode(
	pattern string,
	length int,
	batchCodes map[string]struct{},
) (string, error) {
	const maxAttempts = 100

	for attempt := 0; attempt < maxAttempts; attempt++ {
		candidate, err := generateCode(
			pattern,
			length,
		)

		if err != nil {
			return "", err
		}

		/*
			Check this batch first.
		*/
		if _, exists := batchCodes[candidate]; exists {
			continue
		}

		/*
			Then check vouchers that already exist
			in PostgreSQL.
		*/
		exists, err :=
			s.repo.CodeExists(candidate)

		if err != nil {
			return "", fmt.Errorf(
				"check voucher code uniqueness: %w",
				err,
			)
		}

		if exists {
			continue
		}

		batchCodes[candidate] = struct{}{}

		return candidate, nil
	}

	return "", fmt.Errorf(
		"could not generate a unique %d-character %s voucher code after %d attempts",
		length,
		pattern,
		maxAttempts,
	)
}

func (s *Service) List(
	userID *uuid.UUID,
	isSuperadmin bool,
) ([]Voucher, error) {
	if isSuperadmin || userID == nil {
		return s.repo.List()
	}

	return s.repo.ListForUser(
		*userID,
	)
}

/*
	normalizeCodeLength applies the default when the frontend
	does not provide a length and otherwise requires 4–9.
*/
func normalizeCodeLength(
	length int,
) (int, error) {
	if length == 0 {
		return DefaultVoucherCodeLength, nil
	}

	if length < MinVoucherCodeLength ||
		length > MaxVoucherCodeLength {
		return 0, fmt.Errorf(
			"voucher code length must be between %d and %d characters",
			MinVoucherCodeLength,
			MaxVoucherCodeLength,
		)
	}

	return length, nil
}

/*
	generateCode creates the actual voucher token.

	There is intentionally NO "NF-" prefix.

	If length = 8, the generated code contains exactly
	8 characters.
*/
func generateCode(
	pattern string,
	length int,
) (string, error) {
	var alphabet string

	switch pattern {
	case PatternNumeric:
		alphabet = "0123456789"

	case PatternAlphabetic:
		/*
			I and O are excluded to reduce confusion
			with 1 and 0 when printed.
		*/
		alphabet =
			"ABCDEFGHJKLMNPQRSTUVWXYZ"

	case PatternAlphanumeric:
		/*
			0, 1, I and O are excluded to make voucher
			codes easier to read and type.
		*/
		alphabet =
			"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

	default:
		return "", fmt.Errorf(
			"unknown voucher code character type: %s",
			pattern,
		)
	}

	return randomString(
		alphabet,
		length,
	)
}

/*
	randomString uses crypto/rand so voucher codes are not
	predictable.
*/
func randomString(
	alphabet string,
	length int,
) (string, error) {
	if alphabet == "" {
		return "", fmt.Errorf(
			"voucher code alphabet cannot be empty",
		)
	}

	if length < 1 {
		return "", fmt.Errorf(
			"voucher code length must be greater than zero",
		)
	}

	var builder strings.Builder

	builder.Grow(length)

	max := big.NewInt(
		int64(len(alphabet)),
	)

	for i := 0; i < length; i++ {
		index, err := rand.Int(
			rand.Reader,
			max,
		)

		if err != nil {
			return "", fmt.Errorf(
				"generate secure random voucher code: %w",
				err,
			)
		}

		builder.WriteByte(
			alphabet[index.Int64()],
		)
	}

	return builder.String(), nil
}
