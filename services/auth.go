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

type Claims struct {
	Id        uint   `json:"id"`
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
		CookieDomain = "localhost"
		CookieSameSite = http.SameSiteLaxMode
	}
}

func SetJwtTokensCookies(c *gin.Context, accessToken, refreshToken string, accessExpiration, refreshExpiration time.Time) {
	c.SetCookie("session.xaccess", accessToken, int(time.Until(accessExpiration).Seconds()), "/", CookieDomain, CookieSecure, true)
	c.SetCookie("session.xrefresh", refreshToken, int(time.Until(refreshExpiration).Seconds()), "/", CookieDomain, CookieSecure, true)
	c.SetCookie("session.xstatus", "user_authenticated", int(time.Until(accessExpiration).Seconds()), "/", CookieDomain, CookieSecure, false)
}

func SetCsrfCookie(c *gin.Context, csrfToken string, csrfExpiration time.Time) {
	if config.AppConfig.Environment == "production" {
		c.SetCookie("session.xcsrf", csrfToken, int(time.Until(csrfExpiration).Seconds()), "/", CookieDomain, CookieSecure, false)
	}
}

func ClearTokensCookies(c *gin.Context) {
	c.SetCookie("session.xaccess", "", -1, "/", CookieDomain, CookieSecure, true)
	c.SetCookie("session.xrefresh", "", -1, "/", CookieDomain, CookieSecure, true)
	c.SetCookie("session.xstatus", "", -1, "/", CookieDomain, CookieSecure, false)

	if config.AppConfig.Environment == "production" {
		c.SetCookie("session.xcsrf", "", -1, "/", CookieDomain, CookieSecure, false)
	}
}

func FindUserById(id uint) (*models.User, int, string, error) {
	var user models.User
	err := db.DB.Where("id = ?", id).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusNotFound, "User not found", nil
		}
		return nil, http.StatusInternalServerError, "Database error", err
	}
	return &user, 0, "", nil
}

func FindUserByEmail(email string) (*models.User, int, string, error) {
	var user models.User
	err := db.DB.Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusNotFound, "User not found", nil
		}
		return nil, http.StatusInternalServerError, "Database error", err
	}
	return &user, 0, "", nil
}

func findUserByForgotPasswordToken(token string) (*models.User, int, string, error) {
	var user models.User
	err := db.DB.Where("forgot_password_token = ?", token).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusNotFound, "User not found", nil
		}
		return nil, http.StatusInternalServerError, "Database error", err
	}
	return &user, 0, "", nil
}

func createUser(req validators.SignUpRequest) (int, string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return http.StatusInternalServerError, "Could not hash password", err
	}

	user := models.User{
		Name:     req.Name,
		Email:    req.Email,
		Password: string(hashedPassword),
		Main:     true,
	}

	if err := db.DB.Create(&user).Error; err != nil {
		return http.StatusInternalServerError, "Failed to create user", err
	}

	return 0, "", nil
}

func RegisterUser(req validators.SignUpRequest) (int, string, error) {
	_, status, message, err := FindUserByEmail(req.Email)
	if err != nil && status != http.StatusNotFound {
		return status, message, err
	}
	if status == 0 {
		return http.StatusBadRequest, "Email already exists", nil
	}

	return createUser(req)
}

func UpdateUser(userId uint, req validators.UpdateMeRequest) (*models.User, int, string, error) {
	user, status, message, err := FindUserById(userId)
	if status != 0 {
		return nil, status, message, err
	}

	if req.Email != user.Email {
		_, status, message, err := FindUserByEmail(req.Email)
		if err != nil && status != http.StatusNotFound {
			return nil, status, message, err
		}
		if status == 0 {
			return nil, http.StatusBadRequest, "Email already exists", nil
		}
	}

	user.Name = req.Name
	user.Email = req.Email

	if req.NewPassword != nil && *req.NewPassword != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			return nil, http.StatusInternalServerError, "Could not hash password", err
		}
		user.Password = string(hashedPassword)
	}

	if err := db.DB.Save(user).Error; err != nil {
		return nil, http.StatusInternalServerError, "Database error", err
	}

	return user, 0, "", nil
}

func AuthenticateUser(email, password string) (accessToken, refreshToken string, accessExpiration, refreshExpiration time.Time, status int, message string, err error) {
	user, status, message, err := FindUserByEmail(email)
	if status != 0 {
		return "", "", time.Time{}, time.Time{}, status, message, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", "", time.Time{}, time.Time{}, http.StatusUnauthorized, "Invalid credentials", nil
	}

	accessToken, refreshToken, _, accessExpiration, refreshExpiration, err = generateTokenPair(user.Id)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, http.StatusInternalServerError, "Could not generate tokens", err
	}

	return accessToken, refreshToken, accessExpiration, refreshExpiration, 0, "", nil
}

func RefreshPair(refreshTokenStr string) (accessToken, refreshToken string, accessExpiration, refreshExpiration time.Time, status int, message string, err error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(refreshTokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return JwtKey, nil
	})

	if err != nil || !token.Valid {
		return "", "", time.Time{}, time.Time{}, http.StatusUnauthorized, "Invalid token", nil
	}

	if claims.TokenType != "xrefresh" {
		return "", "", time.Time{}, time.Time{}, http.StatusUnauthorized, "Invalid token type", nil
	}

	user, status, message, err := FindUserById(claims.Id)
	if status != 0 {
		return "", "", time.Time{}, time.Time{}, status, message, err
	}

	accessToken, refreshToken, _, accessExpiration, refreshExpiration, err = generateTokenPair(user.Id)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, http.StatusInternalServerError, "Could not generate tokens", err
	}

	return accessToken, refreshToken, accessExpiration, refreshExpiration, 0, "", nil
}

func ValidateAccessToken(tokenStr string) (*Claims, int, string, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return JwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, http.StatusUnauthorized, "Invalid token", nil
	}

	if claims.TokenType != "xaccess" {
		return nil, http.StatusUnauthorized, "Invalid token type", nil
	}

	return claims, 0, "", nil
}

func generateTokenPair(id uint) (accessToken, refreshToken string, expiresIn int64, accessExpiration, refreshExpiration time.Time, err error) {
	now := time.Now()

	accessExpiration = now.Add(15 * time.Minute)
	accessClaims := &Claims{
		Id:        id,
		TokenType: "xaccess",
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
		TokenType: "xrefresh",
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

func generateUniqueToken(field string, maxAttempts int) (string, error) {
	allowed := map[string]struct{}{
		"forgot_password_token":    {},
		"email_verification_token": {},
	}

	if _, ok := allowed[field]; !ok {
		return "", fmt.Errorf("Unsupported field for uniqueness check: %s", field)
	}

	for range maxAttempts {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		token := hex.EncodeToString(bytes)

		var existing models.User
		condition := fmt.Sprintf("%s = ?", field)
		err := db.DB.Where(condition, token).First(&existing).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return token, nil
			}
			return "", err
		}
	}

	return "", fmt.Errorf("Could not generate unique token for field %s after %d attempts", field, maxAttempts)
}

func SetForgotPasswordToken(user *models.User) (string, int, string, error) {
	token, err := generateUniqueToken("forgot_password_token", 5)
	if err != nil {
		return "", http.StatusInternalServerError, "Could not generate unique token", err
	}

	user.ForgotPasswordToken = token
	if err := db.DB.Save(user).Error; err != nil {
		return "", http.StatusInternalServerError, "Database error", err
	}

	return token, 0, "", nil
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

func IsResetPasswordTokenValid(token string) (bool, int, string, error) {
	_, status, message, err := findUserByForgotPasswordToken(token)
	if status == http.StatusNotFound {
		return false, 0, "", nil
	}
	if status != 0 {
		return false, status, message, err
	}

	return true, 0, "", nil
}

func ChangePasswordWithToken(token, newPassword string) (int, string, error) {
	user, status, message, err := findUserByForgotPasswordToken(token)
	if status == http.StatusNotFound {
		return http.StatusBadRequest, "Invalid or expired reset token", nil
	}
	if status != 0 {
		return status, message, err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return http.StatusInternalServerError, "Could not hash password", err
	}

	user.Password = string(hashedPassword)
	user.ForgotPasswordToken = ""

	if err := db.DB.Save(user).Error; err != nil {
		return http.StatusInternalServerError, "Database error", err
	}

	return 0, "", nil
}

func GenerateCsrfToken() (string, int, string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", http.StatusInternalServerError, "Could not generate CSRF token", err
	}
	return hex.EncodeToString(bytes), 0, "", nil
}
