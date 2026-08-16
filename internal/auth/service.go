package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/database"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	billingPlanName    = "NobliFi Monthly"
	monthlyPriceUGX    = 25000
	trialDuration      = 2 * time.Minute
	authCodeTTL        = 15 * time.Minute
	purposeVerifyEmail = "verify_email"
	purposeResetPass   = "reset_password"
)

var ErrEmailAlreadyRegistered = errors.New("email is already registered")

type Service struct {
	db        *gorm.DB
	jwtSecret string
}

func NewService(db *gorm.DB, jwtSecret string) *Service {
	return &Service{db: db, jwtSecret: jwtSecret}
}

type SignupInput struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	HotspotName string `json:"hotspot_name"`
}

type CodeDelivery struct {
	Sent        bool   `json:"sent"`
	DevCode     string `json:"dev_code,omitempty"`
	Message     string `json:"message"`
	SMTPEnabled bool   `json:"smtp_enabled"`
}

type pendingSignup struct {
	Name         string `json:"name"`
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	HotspotName  string `json:"hotspot_name"`
}

func encodePendingSignup(input SignupInput, passwordHash string) (string, error) {
	payload, err := json.Marshal(pendingSignup{
		Name:         input.Name,
		Email:        input.Email,
		PasswordHash: passwordHash,
		HotspotName:  input.HotspotName,
	})
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func decodePendingSignup(raw string) (pendingSignup, error) {
	if strings.TrimSpace(raw) == "" {
		return pendingSignup{}, nil
	}

	var payload pendingSignup
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return pendingSignup{}, err
	}
	return payload, nil
}

func (s *Service) Signup(input SignupInput) (database.User, CodeDelivery, error) {
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.Name = strings.TrimSpace(input.Name)
	input.HotspotName = strings.TrimSpace(input.HotspotName)

	if input.Name == "" {
		return database.User{}, CodeDelivery{}, errors.New("name is required")
	}
	if !isValidEmail(input.Email) {
		return database.User{}, CodeDelivery{}, errors.New("a valid email is required")
	}
	if input.HotspotName == "" {
		return database.User{}, CodeDelivery{}, errors.New("hotspot name is required")
	}
	if len(input.Password) < 8 {
		return database.User{}, CodeDelivery{}, errors.New("password must be at least 8 characters")
	}

	var count int64
	if err := s.db.Model(&database.User{}).Where("email = ?", input.Email).Count(&count).Error; err != nil {
		return database.User{}, CodeDelivery{}, err
	}
	if count > 0 {
		return database.User{}, CodeDelivery{}, ErrEmailAlreadyRegistered
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return database.User{}, CodeDelivery{}, err
	}

	payload, err := encodePendingSignup(input, string(hash))
	if err != nil {
		return database.User{}, CodeDelivery{}, err
	}

	delivery, err := s.issueCode(input.Email, purposeVerifyEmail, payload)
	if err != nil {
		log.Printf("could not issue verification code for %s: %v", input.Email, err)
	}

	return database.User{}, delivery, nil
}

func (s *Service) Login(email, password string) (string, database.User, error) {
	var user database.User
	email = strings.ToLower(strings.TrimSpace(email))
	if err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
		return "", user, errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", user, errors.New("invalid credentials")
	}
	if user.EmailVerifiedAt == nil {
		return "", user, errors.New("email verification is required before login")
	}

	token, err := s.tokenFor(user)
	return token, user, err
}

func (s *Service) VerifyEmail(email, code string) (string, database.User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	authCode, err := s.consumeCode(email, purposeVerifyEmail, code)
	if err != nil {
		return "", database.User{}, err
	}

	var user database.User
	if err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return "", user, err
		}
		pending, pendingErr := decodePendingSignup(authCode.Payload)
		if pendingErr != nil || pending.Email == "" {
			return "", database.User{}, errors.New("account not found")
		}

		trialEndsAt := time.Now().Add(trialDuration)
		user = database.User{
			Name:            pending.Name,
			Email:           pending.Email,
			PasswordHash:    pending.PasswordHash,
			Role:            "admin",
			HotspotName:     pending.HotspotName,
			BillingPlan:     billingPlanName,
			MonthlyPriceUGX: monthlyPriceUGX,
			TrialEndsAt:     &trialEndsAt,
		}
		if err := s.db.Create(&user).Error; err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique") {
				return "", database.User{}, ErrEmailAlreadyRegistered
			}
			return "", database.User{}, err
		}
	}

	now := time.Now()
	user.EmailVerifiedAt = &now
	if err := s.db.Save(&user).Error; err != nil {
		return "", user, err
	}

	token, err := s.tokenFor(user)
	return token, user, err
}

func (s *Service) ResendVerification(email string) (CodeDelivery, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var user database.User
	if err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return CodeDelivery{}, err
		}

		var authCode database.AuthCode
		if err := s.db.Where("email = ? AND purpose = ? AND used_at IS NULL", email, purposeVerifyEmail).
			Order("created_at desc").
			First(&authCode).Error; err != nil {
			return CodeDelivery{}, errors.New("account not found")
		}

		delivery, err := s.issueCode(email, purposeVerifyEmail, authCode.Payload)
		if err != nil {
			log.Printf("could not resend verification code for %s: %v", email, err)
			return delivery, errors.New("could not send verification code")
		}
		return delivery, nil
	}
	if user.EmailVerifiedAt != nil {
		return CodeDelivery{}, errors.New("email is already verified")
	}
	delivery, err := s.issueCode(email, purposeVerifyEmail, "")
	if err != nil {
		log.Printf("could not resend verification code for %s: %v", email, err)
		return delivery, errors.New("could not send verification code")
	}
	return delivery, nil
}

func (s *Service) RequestPasswordReset(email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	var user database.User
	if err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	_, err := s.issueCode(email, purposeResetPass, "")
	return err
}

func (s *Service) ResetPassword(email, code, password string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if _, err := s.consumeCode(email, purposeResetPass, code); err != nil {
		return err
	}

	var user database.User
	if err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
		return errors.New("account not found")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.PasswordHash = string(hash)
	return s.db.Save(&user).Error
}

func (s *Service) UserFromToken(rawToken string) (database.User, error) {
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.jwtSecret), nil
	})
	if errors.Is(err, jwt.ErrTokenExpired) {
		return database.User{}, errors.New("expired token")
	}
	if err != nil || !parsed.Valid {
		return database.User{}, errors.New("invalid token")
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return database.User{}, errors.New("invalid token subject")
	}
	userID, err := uuid.Parse(sub)
	if err != nil {
		return database.User{}, errors.New("invalid token subject")
	}

	var user database.User
	if err := s.db.First(&user, "id = ?", userID).Error; err != nil {
		return database.User{}, errors.New("user not found")
	}
	return user, nil
}

func (s *Service) tokenFor(user database.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   user.ID.String(),
		"email": user.Email,
		"role":  user.Role,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	})
	return token.SignedString([]byte(s.jwtSecret))
}

func (s *Service) issueCode(email, purpose, payload string) (CodeDelivery, error) {
	code, err := newOneTimeCode()
	if err != nil {
		return CodeDelivery{}, err
	}

	now := time.Now()
	if err := s.db.Model(&database.AuthCode{}).
		Where("email = ? AND purpose = ? AND used_at IS NULL", email, purpose).
		Update("used_at", now).Error; err != nil {
		return CodeDelivery{}, err
	}

	authCode := database.AuthCode{
		Email:     email,
		Purpose:   purpose,
		CodeHash:  hashCode(code),
		Payload:   payload,
		ExpiresAt: now.Add(authCodeTTL),
	}
	if err := s.db.Create(&authCode).Error; err != nil {
		return CodeDelivery{}, err
	}

	return sendOneTimeCode(email, purpose, code)
}

func (s *Service) consumeCode(email, purpose, code string) (database.AuthCode, error) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return database.AuthCode{}, errors.New("invalid or expired code")
	}

	var authCode database.AuthCode
	err := s.db.Where("email = ? AND purpose = ? AND used_at IS NULL", email, purpose).
		Order("created_at desc").
		First(&authCode).Error
	if err != nil {
		return database.AuthCode{}, errors.New("invalid or expired code")
	}
	if time.Now().After(authCode.ExpiresAt) || authCode.CodeHash != hashCode(code) {
		return database.AuthCode{}, errors.New("invalid or expired code")
	}

	now := time.Now()
	authCode.UsedAt = &now
	if err := s.db.Save(&authCode).Error; err != nil {
		return database.AuthCode{}, err
	}
	return authCode, nil
}

func isValidEmail(email string) bool {
	if email == "" || strings.Contains(email, " ") {
		return false
	}
	parsed, err := mail.ParseAddress(email)
	return err == nil && strings.EqualFold(parsed.Address, email)
}

func newOneTimeCode() (string, error) {
	var bytes [6]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	for i, value := range bytes {
		bytes[i] = '0' + (value % 10)
	}
	return string(bytes[:]), nil
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func sendOneTimeCode(email, purpose, code string) (CodeDelivery, error) {
	subject := "Your NobliFi one-time code"
	action := "confirm your account"
	if purpose == purposeResetPass {
		action = "reset your password"
	}

	if resendKey := strings.TrimSpace(os.Getenv("RESEND_API_KEY")); resendKey != "" {
		fromEmail := strings.TrimSpace(os.Getenv("RESEND_FROM_EMAIL"))
		if fromEmail == "" {
			fromEmail = "no-reply@noblifi.local"
		}
		fromName := strings.TrimSpace(os.Getenv("RESEND_FROM_NAME"))
		fromHeader := fromEmail
		if fromName != "" {
			fromHeader = fromName + " <" + fromEmail + ">"
		}

		bodyText := "Use this one-time password code to " + action + ": " + code + "\n\nThis code expires in 15 minutes."
		payload := map[string]any{
			"from":    fromHeader,
			"to":      []string{email},
			"subject": subject,
			"text":    bodyText,
		}
		jsonBody, err := json.Marshal(payload)
		if err != nil {
			return CodeDelivery{Sent: false, Message: "Could not prepare email payload."}, err
		}

		req, err := http.NewRequest(http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(jsonBody))
		if err != nil {
			return CodeDelivery{Sent: false, Message: "Could not build email request."}, err
		}
		req.Header.Set("Authorization", "Bearer "+resendKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
		if err != nil {
			return CodeDelivery{Sent: false, Message: "Could not send email via Resend."}, err
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			var errBody any
			_ = json.NewDecoder(resp.Body).Decode(&errBody)
			return CodeDelivery{Sent: false, Message: "Could not send email via Resend."}, errors.New("resend email failed")
		}

		return CodeDelivery{Sent: true, SMTPEnabled: false, Message: "Verification code sent by email."}, nil
	}

	host := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	port := strings.TrimSpace(os.Getenv("SMTP_PORT"))
	from := strings.TrimSpace(os.Getenv("SMTP_FROM"))
	username := strings.TrimSpace(os.Getenv("SMTP_USERNAME"))
	password := os.Getenv("SMTP_PASSWORD")
	if port == "" {
		port = "587"
	}

	if host == "" || from == "" {
		log.Printf("one-time %s code for %s: %s", purpose, email, code)
		return CodeDelivery{
			Sent:        false,
			DevCode:     code,
			Message:     "Resend is not configured; use the displayed development code.",
			SMTPEnabled: false,
		}, nil
	}

	body := "Use this one-time password code to " + action + ": " + code + "\r\n\r\nThis code expires in 15 minutes."
	message := []byte("To: " + email + "\r\n" +
		"From: " + from + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n" +
		body + "\r\n")

	var auth smtp.Auth
	if username != "" || password != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}
	if err := smtp.SendMail(host+":"+port, auth, from, []string{email}, message); err != nil {
		return CodeDelivery{Sent: false, SMTPEnabled: true, Message: "Could not send email through SMTP."}, err
	}
	return CodeDelivery{Sent: true, SMTPEnabled: true, Message: "Verification code sent by email."}, nil
}

func (s *Service) SeedAdmin() error {
	var user database.User
	if err := s.db.Where("email = ?", "admin@noblifi.local").First(&user).Error; err == nil {
		changed := false
		if user.Role != "superadmin" {
			user.Role = "superadmin"
			changed = true
		}
		if user.EmailVerifiedAt == nil {
			now := time.Now()
			user.EmailVerifiedAt = &now
			changed = true
		}
		if changed {
			return s.db.Save(&user).Error
		}
		return nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := time.Now()
	return s.db.Create(&database.User{
		Name:            "NobliFi Admin",
		Email:           "admin@noblifi.local",
		PasswordHash:    string(hash),
		Role:            "superadmin",
		EmailVerifiedAt: &now,
	}).Error
}

func (s *Service) ListUsers() ([]database.User, error) {
	var users []database.User
	err := s.db.Order("created_at desc").Find(&users).Error
	return users, err
}
