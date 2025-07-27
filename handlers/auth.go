// handlers/auth.go
package handlers

import (
	"go-jwt-api/services"
	"go-jwt-api/validators"
	"net/http"

	"github.com/gin-gonic/gin"
)

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

	if err := services.RegisterUser(req); err != nil {
		switch err.Error() {
		case "username already exists":
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		case "email already exists":
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email already exists"})
		case "could not hash password":
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
		case "failed to create user":
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
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

	accessToken, refreshToken, accessExpiration, refreshExpiration, err := services.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		switch err.Error() {
		case "user not found":
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		case "incorrect password":
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect password"})
		case "could not generate tokens":
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate tokens"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	services.SetTokenCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)

	c.JSON(http.StatusOK, gin.H{"message": "Sign in successful"})
}

func Refresh(c *gin.Context) {
	refreshTokenStr, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token not provided"})
		return
	}

	accessToken, refreshToken, accessExpiration, refreshExpiration, err := services.RefreshPair(refreshTokenStr)
	if err != nil {
		services.ClearTokenCookies(c)
		switch err.Error() {
		case "invalid refresh token":
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		case "invalid token type":
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token type"})
		case "user not found":
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		case "could not generate tokens":
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate tokens"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	services.SetTokenCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)

	c.JSON(http.StatusOK, gin.H{"message": "Refreshed successfully"})
}

func Me(c *gin.Context) {
	username, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found in context"})
		return
	}

	user, err := services.GetUserByUsername(username.(string))
	if err != nil {
		switch err.Error() {
		case "user not found":
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		default:
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
	services.ClearTokenCookies(c)
	c.JSON(http.StatusOK, gin.H{"message": "Sign out successful"})
}
