// auth/auth.go
package auth

import (
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

type Claims struct {
	Username  string `json:"username"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

func setTokenCookies(c *gin.Context, accessToken, refreshToken string, accessExpiration, refreshExpiration time.Time) {
	c.SetCookie("access_token", accessToken, int(time.Until(accessExpiration).Seconds()), "/", CookieDomain, CookieSecure, true)
	c.SetCookie("refresh_token", refreshToken, int(time.Until(refreshExpiration).Seconds()), "/", CookieDomain, CookieSecure, true)
	c.SetCookie("auth_status", "authenticated", int(time.Until(accessExpiration).Seconds()), "/", CookieDomain, CookieSecure, false)
}

func clearTokenCookies(c *gin.Context) {
	c.SetCookie("access_token", "", -1, "/", CookieDomain, CookieSecure, true)
	c.SetCookie("refresh_token", "", -1, "/", CookieDomain, CookieSecure, true)
	c.SetCookie("auth_status", "", -1, "/", CookieDomain, CookieSecure, false)
}

func SignUp(c *gin.Context) {
	var req validators.SignUpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signup request"})
		return
	}
	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		c.JSON(http.StatusBadRequest, gin.H{"validation_errors": validationErrors})
		return
	}

	var existingUser models.User
	if err := db.DB.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	} else if err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if err := db.DB.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already exists"})
		return
	} else if err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
		return
	}

	user := models.User{
		Username: req.Username,
		Email:    req.Email,
		Password: string(hashedPassword),
	}

	if err := db.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

func SignIn(c *gin.Context) {
	var req validators.SignInRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signin request"})
		return
	}
	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		c.JSON(http.StatusBadRequest, gin.H{"validation_errors": validationErrors})
		return
	}

	var user models.User
	if err := db.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect password"})
		return
	}

	accessToken, refreshToken, _, accessExpiration, refreshExpiration, err := generateTokenPair(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate tokens"})
		return
	}

	setTokenCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)

	c.JSON(http.StatusOK, gin.H{"message": "Sign in successful"})
}

func RefreshToken(c *gin.Context) {
	var refreshTokenStr string

	var err error
	refreshTokenStr, err = c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token not provided"})
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(refreshTokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return JwtKey, nil
	})

	if err != nil || !token.Valid {
		clearTokenCookies(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	if claims.TokenType != "refresh" {
		clearTokenCookies(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token type"})
		return
	}

	var user models.User
	if err := db.DB.Where("username = ?", claims.Username).First(&user).Error; err != nil {
		clearTokenCookies(c)
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	accessToken, refreshToken, _, accessExpiration, refreshExpiration, err := generateTokenPair(claims.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate tokens"})
		return
	}

	setTokenCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)

	c.JSON(http.StatusOK, gin.H{"message": "Access token refreshed successfully"})
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

func Me(c *gin.Context) {
	username, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found in context"})
		return
	}

	var user models.User
	if err := db.DB.Where("username = ?", username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
		},
	})
}

func SignOut(c *gin.Context) {
	clearTokenCookies(c)
	c.JSON(http.StatusOK, gin.H{"message": "Sign out successful"})
}
