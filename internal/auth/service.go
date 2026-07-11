package auth

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/database"
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

func (s *Service) Signup(input SignupInput) (string, database.User, error) {
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.Name = strings.TrimSpace(input.Name)

	if input.Name == "" {
		return "", database.User{}, errors.New("name is required")
	}
	if input.Email == "" {
		return "", database.User{}, errors.New("email is required")
	}
	if len(input.Password) < 8 {
		return "", database.User{}, errors.New("password must be at least 8 characters")
	}

	var count int64
	if err := s.db.Model(&database.User{}).Where("email = ?", input.Email).Count(&count).Error; err != nil {
		return "", database.User{}, err
	}
	if count > 0 {
		return "", database.User{}, errors.New("email is already registered")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return "", database.User{}, err
	}

	user := database.User{
		Name:         input.Name,
		Email:        input.Email,
		PasswordHash: string(hash),
		Role:         "admin",
	}
	if err := s.db.Create(&user).Error; err != nil {
		return "", database.User{}, err
	}

	token, err := s.tokenFor(user)
	return token, user, err
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

	token, err := s.tokenFor(user)
	return token, user, err
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
	var count int64
	if err := s.db.Model(&database.User{}).Where("email = ?", "admin@noblifi.local").Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.db.Create(&database.User{
		Name:         "NobliFi Admin",
		Email:        "admin@noblifi.local",
		PasswordHash: string(hash),
		Role:         "admin",
	}).Error
}
