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

func RegisterUser(req validators.SignUpRequest) error {
	var existingUser models.User
	if err := db.DB.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
		return errors.New("username already exists")
	} else if err != gorm.ErrRecordNotFound {
		return errors.New("database error")
	}

	if err := db.DB.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		return errors.New("email already exists")
	} else if err != gorm.ErrRecordNotFound {
		return errors.New("database error")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("could not hash password")
	}

	user := models.User{
		Username: req.Username,
		Email:    req.Email,
		Password: string(hashedPassword),
	}

	if err := db.DB.Create(&user).Error; err != nil {
		return errors.New("failed to create user")
	}

	return nil
}

func AuthenticateUser(username, password string) (accessToken, refreshToken string, accessExpiration, refreshExpiration time.Time, err error) {
	var user models.User
	if err := db.DB.Where("username = ?", username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", "", time.Time{}, time.Time{}, errors.New("user not found")
		}
		return "", "", time.Time{}, time.Time{}, errors.New("database error")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", "", time.Time{}, time.Time{}, errors.New("incorrect password")
	}

	accessToken, refreshToken, _, accessExpiration, refreshExpiration, err = generateTokenPair(user.Username)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, errors.New("could not generate tokens")
	}

	return accessToken, refreshToken, accessExpiration, refreshExpiration, nil
}

func RefreshPair(refreshTokenStr string) (accessToken, refreshToken string, accessExpiration, refreshExpiration time.Time, err error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(refreshTokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return JwtKey, nil
	})

	if err != nil || !token.Valid {
		return "", "", time.Time{}, time.Time{}, errors.New("invalid refresh token")
	}

	if claims.TokenType != "refresh" {
		return "", "", time.Time{}, time.Time{}, errors.New("invalid token type")
	}

	var user models.User
	if err := db.DB.Where("username = ?", claims.Username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", "", time.Time{}, time.Time{}, errors.New("user not found")
		}
		return "", "", time.Time{}, time.Time{}, errors.New("database error")
	}

	accessToken, refreshToken, _, accessExpiration, refreshExpiration, err = generateTokenPair(claims.Username)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, errors.New("could not generate tokens")
	}

	return accessToken, refreshToken, accessExpiration, refreshExpiration, nil
}

func GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	if err := db.DB.Where("username = ?", username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.New("user not found")
		}
		return nil, errors.New("database error")
	}
	return &user, nil
}

func ValidateAccessToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return JwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	if claims.TokenType != "access" {
		return nil, errors.New("invalid token type")
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
