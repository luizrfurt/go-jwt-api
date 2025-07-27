// handlers/auth.go
package handlers

import (
	"go-jwt-api/exceptions"
	"go-jwt-api/services"
	"go-jwt-api/utils"
	"go-jwt-api/validators"
	"net/http"

	"github.com/gin-gonic/gin"
)

func SignUp(c *gin.Context) {
	var req validators.SignUpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		exceptions.Error(c, http.StatusBadRequest, "Invalid signup request.")
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		exceptions.ValidationError(c, validationErrors)
		return
	}

	if err := services.RegisterUser(req); err != nil {
		exceptions.AuthError(c, err)
		return
	}

	utils.SendJSON(c, http.StatusCreated, gin.H{"message": "User registered successfully."})
}

func SignIn(c *gin.Context) {
	var req validators.SignInRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		exceptions.Error(c, http.StatusBadRequest, "Invalid signin request.")
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		exceptions.ValidationError(c, validationErrors)
		return
	}

	accessToken, refreshToken, accessExpiration, refreshExpiration, err := services.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		exceptions.AuthError(c, err)
		return
	}

	services.SetTokenCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Sign in successful."})
}

func Refresh(c *gin.Context) {
	refreshTokenStr, err := c.Cookie("refresh_token")
	if err != nil {
		exceptions.Error(c, http.StatusBadRequest, "Refresh token not provided.")
		return
	}

	accessToken, refreshToken, accessExpiration, refreshExpiration, err := services.RefreshPair(refreshTokenStr)
	if err != nil {
		services.ClearTokenCookies(c)
		exceptions.AuthError(c, err)
		return
	}

	services.SetTokenCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Refreshed successfully."})
}

func Me(c *gin.Context) {
	username, exists := c.Get("user")
	if !exists {
		exceptions.Error(c, http.StatusInternalServerError, "User not found in context.")
		return
	}

	user, err := services.GetUserByUsername(username.(string))
	if err != nil {
		customMappings := map[error]exceptions.ErrorMapping{
			services.ErrUserNotFound: {
				StatusCode: http.StatusNotFound,
				Message:    "User not found.",
			},
		}
		exceptions.AuthErrorWithCustomStatus(c, err, customMappings)
		return
	}

	type UserResponse struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"user": UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
	}})
}

func SignOut(c *gin.Context) {
	services.ClearTokenCookies(c)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Sign out successful."})
}
