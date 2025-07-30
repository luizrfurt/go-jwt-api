// services/auth.go
package services

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"go-jwt-api/config"
	"go-jwt-api/db"
	"go-jwt-api/models"
	"go-jwt-api/utils"
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
	ErrInvalidResetToken = errors.New("invalid or expired reset token")
)

type Claims struct {
	Id        uint   `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

func InitAuthConfig() {
	JwtKey = []byte(config.AppConfig.JwtKey)

	if config.AppConfig.Environment == "production" {
		CookieSecure = true
		CookieDomain = "https://your-domain.com"
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

func findUserByID(id uint) (*models.User, error) {
	var user models.User
	err := db.DB.Where("id = ?", id).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	return &user, nil
}

func findUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := db.DB.Where("username = ?", username).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	return &user, nil
}

func FindUserByEmail(email string) (*models.User, error) {
	var user models.User
	err := db.DB.Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	return &user, nil
}

func findUserByForgotPasswordToken(token string) (*models.User, error) {
	var user models.User
	err := db.DB.Where("forgot_password_token = ?", token).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	return &user, nil
}

func createUser(req validators.SignUpRequest) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHashPassword, err)
	}

	user := models.User{
		Name:     req.Name,
		Username: req.Username,
		Email:    req.Email,
		Password: string(hashedPassword),
	}

	if err := db.DB.Create(&user).Error; err != nil {
		return fmt.Errorf("%w: %v", ErrCreateUser, err)
	}

	return nil
}

func RegisterUser(req validators.SignUpRequest) error {
	_, err := findUserByUsername(req.Username)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return err
	}
	if err == nil {
		return ErrUsernameExists
	}

	_, err = FindUserByEmail(req.Email)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return err
	}
	if err == nil {
		return ErrEmailExists
	}

	return createUser(req)
}

func UpdateUser(userID uint, req validators.MeEditRequest) (*models.User, error) {
	user, err := findUserByID(userID)
	if err != nil {
		return nil, err
	}

	if req.Username != user.Username {
		_, err := findUserByUsername(req.Username)
		if err != nil && !errors.Is(err, ErrUserNotFound) {
			return nil, err
		}
		if err == nil {
			return nil, ErrUsernameExists
		}
	}

	if req.Email != user.Email {
		_, err := FindUserByEmail(req.Email)
		if err != nil && !errors.Is(err, ErrUserNotFound) {
			return nil, err
		}
		if err == nil {
			return nil, ErrEmailExists
		}
	}

	user.Name = req.Name
	user.Username = req.Username
	user.Email = req.Email

	if req.NewPassword != nil && *req.NewPassword != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrHashPassword, err)
		}
		user.Password = string(hashedPassword)
	}

	if err := db.DB.Save(user).Error; err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}

	return user, nil
}

func AuthenticateUser(username, password string) (accessToken, refreshToken string, accessExpiration, refreshExpiration time.Time, err error) {
	user, err := findUserByUsername(username)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", "", time.Time{}, time.Time{}, ErrIncorrectPassword
	}

	accessToken, refreshToken, _, accessExpiration, refreshExpiration, err = generateTokenPair(user.ID, user.Username, user.Email)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("%w: %v", ErrGenerateTokens, err)
	}

	return accessToken, refreshToken, accessExpiration, refreshExpiration, nil
}

func RefreshPair(refreshTokenStr string) (accessToken, refreshToken string, accessExpiration, refreshExpiration time.Time, err error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(refreshTokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return JwtKey, nil
	})

	if err != nil || !token.Valid {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if claims.TokenType != "refresh" {
		return "", "", time.Time{}, time.Time{}, ErrInvalidTokenType
	}

	user, err := findUserByUsername(claims.Username)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}

	accessToken, refreshToken, _, accessExpiration, refreshExpiration, err = generateTokenPair(user.ID, user.Username, user.Email)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("%w: %v", ErrGenerateTokens, err)
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
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if claims.TokenType != "access" {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}

func generateTokenPair(id uint, username, email string) (accessToken, refreshToken string, expiresIn int64, accessExpiration, refreshExpiration time.Time, err error) {
	now := time.Now()

	accessExpiration = now.Add(15 * time.Minute)
	accessClaims := &Claims{
		Id:        id,
		Username:  username,
		Email:     email,
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
		Id:        id,
		Username:  username,
		Email:     email,
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

func generateForgotPasswordToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func SetForgotPasswordToken(user *models.User) (string, error) {
	token, err := generateForgotPasswordToken()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrGenerateTokens, err)
	}

	user.ForgotPasswordToken = token
	if err := db.DB.Save(user).Error; err != nil {
		return "", fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}

	return token, nil
}

func SendPasswordRecoveryEmail(user *models.User, token string) error {
	link := fmt.Sprintf("http://localhost:%s/reset-password/%s", config.AppConfig.PortWeb, token)
	body := fmt.Sprintf(`
		<div style="font-family: Arial, sans-serif; color: #333;">
			<h2 style="color: #2c3e50;">Password Recovery</h2>
			<p>Hello,</p>
			<p>Please click the button below to reset your password:</p>
			<a href="%s" style="
			display: inline-block;
			padding: 10px 20px;
			margin: 15px 0;
			background-color: #005B73;
			color: white;
			text-decoration: none;
			border-radius: 5px;
			font-weight: bold;
			" 
			onmouseover="this.style.backgroundColor='#007991';" 
			onmouseout="this.style.backgroundColor='#005B73';"
			>Reset Password</a>
			<p>If you didn't request a password reset, please ignore this email.</p>
			<p>Thanks,<br/>Your Company Team</p>
		</div>
	`, link)

	if err := utils.SendEmail(user.Email, "Password Recovery", body); err != nil {
		return fmt.Errorf("failed to send recovery email: %w", err)
	}

	return nil
}

func IsResetPasswordTokenValid(token string) (bool, error) {
	_, err := findUserByForgotPasswordToken(token)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}

	return true, nil
}

func ChangePasswordWithToken(token, newPassword string) error {
	user, err := findUserByForgotPasswordToken(token)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return ErrInvalidResetToken
		}
		return fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHashPassword, err)
	}

	user.Password = string(hashedPassword)
	user.ForgotPasswordToken = ""

	if err := db.DB.Save(user).Error; err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}

	return nil
}
