// auth/auth.go
package auth

import (
	"go-jwt-api/db"
	"go-jwt-api/models"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var JwtKey = []byte("secret-key")

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username  string `json:"username"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

type TokenResponse struct {
	Message      string `json:"message,omitempty"`
	//AccessToken  string `json:"access_token"`
	//RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func setTokenCookies(c *gin.Context, accessToken, refreshToken string, accessExpiration, refreshExpiration time.Time) {
	c.SetCookie("access_token", accessToken, int(time.Until(accessExpiration).Seconds()), "/", "", false, true)
	c.SetCookie("refresh_token", refreshToken, int(time.Until(refreshExpiration).Seconds()), "/", "", false, true)
	c.SetCookie("auth_status", "authenticated", int(time.Until(accessExpiration).Seconds()), "/", "", false, false)
}

func clearTokenCookies(c *gin.Context) {
	c.SetCookie("access_token", "", -1, "/", "", false, true)
	c.SetCookie("refresh_token", "", -1, "/", "", false, true)
	c.SetCookie("auth_status", "", -1, "/", "", false, false)
}

func SignUp(c *gin.Context) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var existingUser models.User
	if err := db.DB.Where("username = ?", creds.Username).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User already exists"})
		return
	} else if err != gorm.ErrRecordNotFound {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
		return
	}

	user := models.User{
		Username: creds.Username,
		Password: string(hashedPassword),
	}

	if err := db.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered"})
}

func SignIn(c *gin.Context) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var user models.User
	if err := db.DB.Where("username = ?", creds.Username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect password"})
		return
	}

	accessToken, refreshToken, expiresIn, accessExpiration, refreshExpiration, err := generateTokenPair(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate tokens"})
		return
	}

	setTokenCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)

	response := TokenResponse{
		Message:      "Sign in successful",
		//AccessToken:  accessToken,
		//RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
	}

	c.JSON(http.StatusOK, response)
}

func RefreshToken(c *gin.Context) {
	var req RefreshRequest
	var refreshTokenStr string

	if err := c.BindJSON(&req); err == nil && req.RefreshToken != "" {
		refreshTokenStr = req.RefreshToken
	} else {
		var err error
		refreshTokenStr, err = c.Cookie("refresh_token")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token not provided"})
			return
		}
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

	accessToken, refreshToken, expiresIn, accessExpiration, refreshExpiration, err := generateTokenPair(claims.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate tokens"})
		return
	}

	setTokenCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)

	response := TokenResponse{
		Message:      "Access token refreshed successfully",
		//AccessToken:  accessToken,
		//RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
	}

	c.JSON(http.StatusOK, response)
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
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found in context"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": user})
}

func SignOut(c *gin.Context) {
	clearTokenCookies(c)
	c.JSON(http.StatusOK, gin.H{"message": "Signout successful (client-side tokens must be discarded)"})
}
