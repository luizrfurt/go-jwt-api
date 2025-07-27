// services/auth.go
package services

import (
	"errors"
	"go-jwt-api/config"
	"go-jwt-api/db"
	"go-jwt-api/models"
	"go-jwt-api/validators"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	JwtKey         []byte
	CookieSecure   bool
	CookieDomain   string
	CookieSameSite http.SameSite
)

var (
	ErrUsernameExists    = errors.New("username already exists")
	ErrEmailExists       = errors.New("email already exists")
	ErrUserNotFound      = errors.New("user not found")
	ErrDatabaseError     = errors.New("database error")
	ErrHashPassword      = errors.New("could not hash password")
	ErrCreateUser        = errors.New("failed to create user")
	ErrIncorrectPassword = errors.New("incorrect password")
	ErrGenerateTokens    = errors.New("could not generate tokens")
	ErrInvalidToken      = errors.New("invalid token")
	ErrInvalidTokenType  = errors.New("invalid token type")
)

type Claims struct {
	Username  string `json:"username"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

func InitAuthConfig() {
	JwtKey = []byte(config.AppConfig.JwtKey)

	if config.AppConfig.Environment == "production" {
		CookieSecure = true
		CookieDomain = "your-domain.com"
		CookieSameSite = http.SameSiteStrictMode
	} else {
		CookieSecure = false
		CookieDomain = ""
		CookieSameSite = http.SameSiteLaxMode
	}
}

func SetTokenCookies(c *gin.Context, accessToken, refreshToken string, accessExpiration, refreshExpiration time.Time) {
	c.SetCookie("access_token", accessToken, int(time.Until(accessExpiration).Seconds()), "/", CookieDomain, CookieSecure, true)
	c.SetCookie("refresh_token", refreshToken, int(time.Until(refreshExpiration).Seconds()), "/", CookieDomain, CookieSecure, true)
	c.SetCookie("auth_status", "authenticated", int(time.Until(accessExpiration).Seconds()), "/", CookieDomain, CookieSecure, false)
}

func ClearTokenCookies(c *gin.Context) {
	c.SetCookie("access_token", "", -1, "/", CookieDomain, CookieSecure, true)
	c.SetCookie("refresh_token", "", -1, "/", CookieDomain, CookieSecure, true)
	c.SetCookie("auth_status", "", -1, "/", CookieDomain, CookieSecure, false)
}

func findUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := db.DB.Where("username = ?", username).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, ErrDatabaseError
	}
	return &user, nil
}

func findUserByEmail(email string) (*models.User, error) {
	var user models.User
	err := db.DB.Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, ErrDatabaseError
	}
	return &user, nil
}

func createUser(req validators.SignUpRequest) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return ErrHashPassword
	}

	user := models.User{
		Username: req.Username,
		Email:    req.Email,
		Password: string(hashedPassword),
	}

	if err := db.DB.Create(&user).Error; err != nil {
		return ErrCreateUser
	}

	return nil
}

func RegisterUser(req validators.SignUpRequest) error {
	_, err := findUserByUsername(req.Username)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
	}
	if err == nil {
		return ErrUsernameExists
	}

	_, err = findUserByEmail(req.Email)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return err
	}
	if err == nil {
		return ErrEmailExists
	}

	return createUser(req)
}

func AuthenticateUser(username, password string) (accessToken, refreshToken string, accessExpiration, refreshExpiration time.Time, err error) {
	user, err := findUserByUsername(username)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", "", time.Time{}, time.Time{}, ErrIncorrectPassword
	}

	accessToken, refreshToken, _, accessExpiration, refreshExpiration, err = generateTokenPair(user.Username)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, ErrGenerateTokens
	}

	return accessToken, refreshToken, accessExpiration, refreshExpiration, nil
}

func RefreshPair(refreshTokenStr string) (accessToken, refreshToken string, accessExpiration, refreshExpiration time.Time, err error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(refreshTokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return JwtKey, nil
	})

	if err != nil || !token.Valid {
		return "", "", time.Time{}, time.Time{}, ErrInvalidToken
	}

	if claims.TokenType != "refresh" {
		return "", "", time.Time{}, time.Time{}, ErrInvalidTokenType
	}

	_, err = findUserByUsername(claims.Username)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}

	accessToken, refreshToken, _, accessExpiration, refreshExpiration, err = generateTokenPair(claims.Username)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, ErrGenerateTokens
	}

	return accessToken, refreshToken, accessExpiration, refreshExpiration, nil
}

func GetUserByUsername(username string) (*models.User, error) {
	return findUserByUsername(username)
}

func ValidateAccessToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return JwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims.TokenType != "access" {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}

func generateTokenPair(username string) (accessToken, refreshToken string, expiresIn int64, accessExpiration, refreshExpiration time.Time, err error) {
	now := time.Now()

	accessExpiration = now.Add(15 * time.Minute)
	accessClaims := &Claims{
		Username:  username,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessExpiration),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	accessTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessToken, err = accessTokenObj.SignedString(JwtKey)
	if err != nil {
		return "", "", 0, time.Time{}, time.Time{}, err
	}

	refreshExpiration = now.Add(7 * 24 * time.Hour)
	refreshClaims := &Claims{
		Username:  username,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExpiration),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	refreshTokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshToken, err = refreshTokenObj.SignedString(JwtKey)
	if err != nil {
		return "", "", 0, time.Time{}, time.Time{}, err
	}

	expiresIn = int64(accessExpiration.Sub(now).Seconds())
	return accessToken, refreshToken, expiresIn, accessExpiration, refreshExpiration, nil
}
