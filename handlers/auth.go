// handlers/auth.go
package handlers

import (
	"errors"
	"go-jwt-api/services"
	"go-jwt-api/validators"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ErrorResponse struct {
	Error   string            `json:"error"`
	Details map[string]string `json:"details,omitempty"`
}

func handleServiceError(c *gin.Context, err error) {
	var statusCode int
	var message string

	switch {
	case errors.Is(err, services.ErrUsernameExists):
		statusCode = http.StatusBadRequest
		message = "Username already exists"
	case errors.Is(err, services.ErrEmailExists):
		statusCode = http.StatusBadRequest
		message = "Email already exists"
	case errors.Is(err, services.ErrUserNotFound):
		statusCode = http.StatusUnauthorized
		message = "User not found"
	case errors.Is(err, services.ErrIncorrectPassword):
		statusCode = http.StatusUnauthorized
		message = "Incorrect password"
	case errors.Is(err, services.ErrInvalidToken):
		statusCode = http.StatusUnauthorized
		message = "Invalid token"
	case errors.Is(err, services.ErrInvalidTokenType):
		statusCode = http.StatusUnauthorized
		message = "Invalid token type"
	case errors.Is(err, services.ErrHashPassword):
		statusCode = http.StatusInternalServerError
		message = "Could not hash password"
	case errors.Is(err, services.ErrCreateUser):
		statusCode = http.StatusInternalServerError
		message = "Failed to create user"
	case errors.Is(err, services.ErrGenerateTokens):
		statusCode = http.StatusInternalServerError
		message = "Could not generate tokens"
	case errors.Is(err, services.ErrDatabaseError):
		statusCode = http.StatusInternalServerError
		message = "Database error"
	default:
		statusCode = http.StatusInternalServerError
		message = "Internal server error"
	}

	c.JSON(statusCode, ErrorResponse{Error: message})
}

func SignUp(c *gin.Context) {
	var req validators.SignUpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid signup request"})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		c.JSON(http.StatusBadRequest, gin.H{"validation_errors": validationErrors})
		return
	}

	if err := services.RegisterUser(req); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

func SignIn(c *gin.Context) {
	var req validators.SignInRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid signin request"})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		c.JSON(http.StatusBadRequest, gin.H{"validation_errors": validationErrors})
		return
	}

	accessToken, refreshToken, accessExpiration, refreshExpiration, err := services.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	services.SetTokenCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)
	c.JSON(http.StatusOK, gin.H{"message": "Sign in successful"})
}

func Refresh(c *gin.Context) {
	refreshTokenStr, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Refresh token not provided"})
		return
	}

	accessToken, refreshToken, accessExpiration, refreshExpiration, err := services.RefreshPair(refreshTokenStr)
	if err != nil {
		services.ClearTokenCookies(c)
		handleServiceError(c, err)
		return
	}

	services.SetTokenCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)
	c.JSON(http.StatusOK, gin.H{"message": "Refreshed successfully"})
}

func Me(c *gin.Context) {
	username, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "User not found in context"})
		return
	}

	user, err := services.GetUserByUsername(username.(string))
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, ErrorResponse{Error: "User not found"})
			return
		}
		handleServiceError(c, err)
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
