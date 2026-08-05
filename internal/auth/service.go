package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/database"
	routerdb "github.com/noblifi/noblifi/backend/internal/routers"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Service struct {
	db        *gorm.DB
	jwtSecret string
}

func NewService(db *gorm.DB, jwtSecret string) *Service {
	return &Service{db: db, jwtSecret: jwtSecret}
}

type SignupInput struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AccountDetails struct {
	User    database.User     `json:"user"`
	Routers []routerdb.Router `json:"routers"`
}

func (s *Service) Signup(input SignupInput) (database.User, error) {
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.Name = strings.TrimSpace(input.Name)

	if input.Name == "" {
		return database.User{}, errors.New("name is required")
	}
	if input.Email == "" {
		return database.User{}, errors.New("email is required")
	}
	if len(input.Password) < 8 {
		return database.User{}, errors.New("password must be at least 8 characters")
	}

	var count int64
	if err := s.db.Model(&database.User{}).Where("email = ?", input.Email).Count(&count).Error; err != nil {
		return database.User{}, err
	}
	if count > 0 {
		return database.User{}, errors.New("email is already registered")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return database.User{}, err
	}

	user := database.User{
		Name:          input.Name,
		Email:         input.Email,
		PasswordHash:  string(hash),
		Role:          "client",
		AccountStatus: "pending",
		RouterLimit:   3,
	}
	if err := s.db.Create(&user).Error; err != nil {
		return database.User{}, err
	}

	return user, nil
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
	if user.Role != "superadmin" && user.AccountStatus != "approved" {
		return "", user, errors.New("account is pending superadmin approval")
	}

	token, err := s.tokenFor(user)
	return token, user, err
}

func (s *Service) ChangePassword(user database.User, currentPassword, newPassword string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)); err != nil {
		return errors.New("current password is incorrect")
	}
	if len(newPassword) < 8 {
		return errors.New("new password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.db.Model(&database.User{}).Where("id = ?", user.ID).Update("password_hash", string(hash)).Error
}

func (s *Service) UserFromToken(rawToken string) (database.User, error) {
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.jwtSecret), nil
	})
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

func (s *Service) Users() ([]database.User, error) {
	var users []database.User
	err := s.db.Order("created_at desc").Find(&users).Error
	return users, err
}

func (s *Service) UserByID(id uuid.UUID) (database.User, error) {
	var user database.User
	if err := s.db.First(&user, "id = ?", id).Error; err != nil {
		return user, errors.New("user not found")
	}
	return user, nil
}

func (s *Service) AccountDetailsByUsername(username string) (AccountDetails, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return AccountDetails{}, errors.New("username is required")
	}
	like := "%" + strings.ToLower(username) + "%"
	var user database.User
	if err := s.db.
		Where("LOWER(name) = ? OR LOWER(email) = ?", strings.ToLower(username), strings.ToLower(username)).
		Or("LOWER(name) LIKE ? OR LOWER(email) LIKE ?", like, like).
		Order("created_at desc").
		First(&user).Error; err != nil {
		return AccountDetails{}, errors.New("user not found")
	}
	var routers []routerdb.Router
	if err := s.db.
		Preload("Interfaces").
		Preload("PortAssignments").
		Preload("SetupSession").
		Preload("NetworkProfile").
		Where("owner_user_id = ? AND deleted_at IS NULL", user.ID).
		Order("created_at desc").
		Find(&routers).Error; err != nil {
		return AccountDetails{}, err
	}
	return AccountDetails{User: user, Routers: routers}, nil
}

func (s *Service) ApproveUser(userID uuid.UUID, routerLimit int) (database.User, error) {
	if routerLimit <= 0 {
		routerLimit = 3
	}
	var user database.User
	if err := s.db.First(&user, "id = ?", userID).Error; err != nil {
		return user, errors.New("user not found")
	}
	now := time.Now().UTC()
	user.AccountStatus = "approved"
	user.RouterLimit = routerLimit
	user.ApprovedAt = &now
	return user, s.db.Save(&user).Error
}

func (s *Service) RequestRouterLimit(user database.User, requestedLimit int, reason string) (database.RouterLimitRequest, error) {
	if requestedLimit <= user.RouterLimit {
		return database.RouterLimitRequest{}, fmt.Errorf("requested limit must be greater than current limit %d", user.RouterLimit)
	}
	request := database.RouterLimitRequest{
		UserID:         user.ID,
		RequestedLimit: requestedLimit,
		Reason:         strings.TrimSpace(reason),
		Status:         "pending",
	}
	return request, s.db.Create(&request).Error
}

func (s *Service) RouterLimitRequests() ([]database.RouterLimitRequest, error) {
	var requests []database.RouterLimitRequest
	err := s.db.Order("created_at desc").Find(&requests).Error
	return requests, err
}

func (s *Service) DecideRouterLimitRequest(requestID, adminID uuid.UUID, approved bool) (database.RouterLimitRequest, error) {
	var request database.RouterLimitRequest
	if err := s.db.First(&request, "id = ?", requestID).Error; err != nil {
		return request, errors.New("router limit request not found")
	}
	if request.Status != "pending" {
		return request, errors.New("router limit request has already been decided")
	}
	now := time.Now().UTC()
	request.DecidedByID = &adminID
	request.DecidedAt = &now
	if approved {
		request.Status = "approved"
		if err := s.db.Model(&database.User{}).Where("id = ?", request.UserID).Update("router_limit", request.RequestedLimit).Error; err != nil {
			return request, err
		}
	} else {
		request.Status = "rejected"
	}
	return request, s.db.Save(&request).Error
}

func (s *Service) CreateConfirmationCode(user database.User, action string) (database.ConfirmationCode, string, error) {
	code := numericCode(6)
	sum := sha256.Sum256([]byte(code))
	confirmation := database.ConfirmationCode{
		UserID:    user.ID,
		Email:     user.Email,
		Action:    strings.TrimSpace(action),
		CodeHash:  hex.EncodeToString(sum[:]),
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
	}
	return confirmation, code, s.db.Create(&confirmation).Error
}

func (s *Service) VerifyConfirmationCode(user database.User, action, code string) error {
	sum := sha256.Sum256([]byte(strings.TrimSpace(code)))
	hash := hex.EncodeToString(sum[:])
	var confirmation database.ConfirmationCode
	err := s.db.Where("user_id = ? AND action = ? AND code_hash = ? AND used_at IS NULL AND expires_at > ?", user.ID, action, hash, time.Now().UTC()).
		Order("created_at desc").
		First(&confirmation).
		Error
	if err != nil {
		return errors.New("invalid or expired confirmation code")
	}
	now := time.Now().UTC()
	confirmation.UsedAt = &now
	return s.db.Save(&confirmation).Error
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

func (s *Service) SeedAdmin() error {
	var existing database.User
	if err := s.db.Where("email = ?", "admin@noblifi.local").First(&existing).Error; err == nil {
		existing.Role = "superadmin"
		existing.AccountStatus = "approved"
		if existing.RouterLimit <= 0 {
			existing.RouterLimit = 1000
		}
		return s.db.Save(&existing).Error
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.db.Create(&database.User{
		Name:          "NobliFi Super Admin",
		Email:         "admin@noblifi.local",
		PasswordHash:  string(hash),
		Role:          "superadmin",
		AccountStatus: "approved",
		RouterLimit:   1000,
	}).Error
}

func numericCode(length int) string {
	if length <= 0 {
		length = 6
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "123456"
	}
	var builder strings.Builder
	for _, value := range buf {
		builder.WriteByte(byte('0' + int(value)%10))
	}
	return builder.String()
}
