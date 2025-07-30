// handlers/auth.go
package handlers

import (
	"fmt"
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

	utils.SendJSON(c, http.StatusCreated, gin.H{"message": "User registered successfully."}, []string{})
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
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Sign in successful."}, []string{})
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
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Refreshed successfully."}, []string{})
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
		Name     string `json:"name"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"user": UserResponse{
		ID:       user.ID,
		Name:     user.Name,
		Username: user.Username,
		Email:    user.Email,
	}}, []string{})
}

func UpdateMe(c *gin.Context) {
	var req validators.UpdateMeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		exceptions.Error(c, http.StatusBadRequest, "Invalid me-edit request.")
		return
	}
	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		exceptions.ValidationError(c, validationErrors)
		return
	}

	userID, exists := c.Get("id")
	if !exists {
		exceptions.Error(c, http.StatusInternalServerError, "User ID not found in context.")
		return
	}

	updatedUser, err := services.UpdateUser(userID.(uint), req)
	if err != nil {
		customMappings := map[error]exceptions.ErrorMapping{
			services.ErrUserNotFound: {
				StatusCode: http.StatusNotFound,
				Message:    "User not found.",
			},
			services.ErrUsernameExists: {
				StatusCode: http.StatusConflict,
				Message:    "Username is already in use by another user.",
			},
			services.ErrEmailExists: {
				StatusCode: http.StatusConflict,
				Message:    "Email is already in use by another user.",
			},
		}
		exceptions.AuthErrorWithCustomStatus(c, err, customMappings)
		return
	}

	type UserResponse struct {
		ID       uint   `json:"id"`
		Name     string `json:"name"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	utils.SendJSON(c, http.StatusOK, gin.H{
		"message": "Profile updated successfully.",
		"user": UserResponse{
			ID:       updatedUser.ID,
			Name:     updatedUser.Name,
			Username: updatedUser.Username,
			Email:    updatedUser.Email,
		},
	}, []string{})
}

func SignOut(c *gin.Context) {
	services.ClearTokenCookies(c)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Sign out successful."}, []string{})
}

func ForgotPassword(c *gin.Context) {
	var req validators.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		exceptions.Error(c, http.StatusBadRequest, "Invalid forgot-password request.")
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		exceptions.ValidationError(c, validationErrors)
		return
	}

	user, err := services.FindUserByEmail(req.Email)
	if err != nil {
		customMappings := map[error]exceptions.ErrorMapping{
			services.ErrUserNotFound: {
				StatusCode: http.StatusNotFound,
				Message:    "User with this email was not found.",
			},
		}
		exceptions.AuthErrorWithCustomStatus(c, err, customMappings)
		return
	}

	token, err := services.SetForgotPasswordToken(user)
	if err != nil {
		exceptions.AuthError(c, err)
		return
	}

	if err := services.SendPasswordRecoveryEmail(user, token); err != nil {
		exceptions.Error(c, http.StatusInternalServerError, "Failed to send recovery email.")
		return
	}

	utils.SendJSON(c, http.StatusOK, gin.H{
		"message": fmt.Sprintf("Password recovery instructions sent to %s.", user.Email),
	}, []string{})
}

func ResetPasswordValidToken(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		exceptions.Error(c, http.StatusBadRequest, "Token is required.")
		return
	}

	isValid, err := services.IsResetPasswordTokenValid(token)
	if err != nil {
		exceptions.AuthError(c, err)
		return
	}

	if !isValid {
		exceptions.Error(c, http.StatusBadRequest, "Invalid or expired token.")
		return
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Token is valid."}, []string{})
}

func ResetPasswordChangePassword(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		exceptions.Error(c, http.StatusBadRequest, "Token is required.")
		return
	}

	isValid, err := services.IsResetPasswordTokenValid(token)
	if err != nil {
		exceptions.AuthError(c, err)
		return
	}

	if !isValid {
		exceptions.Error(c, http.StatusBadRequest, "Invalid or expired token.")
		return
	}

	var req validators.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		exceptions.Error(c, http.StatusBadRequest, "Invalid reset-password request.")
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		exceptions.ValidationError(c, validationErrors)
		return
	}

	if err := services.ChangePasswordWithToken(token, req.NewPassword); err != nil {
		customMappings := map[error]exceptions.ErrorMapping{
			services.ErrInvalidResetToken: {
				StatusCode: http.StatusBadRequest,
				Message:    "Invalid or expired reset token.",
			},
		}
		exceptions.AuthErrorWithCustomStatus(c, err, customMappings)
		return
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Password changed successfully."}, []string{})
}
