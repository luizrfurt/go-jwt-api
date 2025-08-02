package handlers

import (
	"fmt"
	"go-jwt-api/services"
	"go-jwt-api/utils"
	"go-jwt-api/validators"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func SignUp(c *gin.Context) {
	var req validators.SignUpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid signup request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	if err := services.RegisterUser(req); err != nil {
		status, message := services.MapAuthError(err)
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	utils.SendJSON(c, http.StatusCreated, gin.H{"message": "User registered successfully"}, []string{})
}

func SignIn(c *gin.Context) {
	var req validators.SignInRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid signin request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	accessToken, refreshToken, accessExpiration, refreshExpiration, err := services.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		status, message := services.MapAuthError(err)
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	services.SetJwtTokensCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Sign in successful"}, []string{})
}

func Refresh(c *gin.Context) {
	refreshTokenStr, err := c.Cookie("session.xrefresh")
	if err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Refresh token not provided"}, []string{})
		return
	}

	accessToken, refreshToken, accessExpiration, refreshExpiration, err := services.RefreshPair(refreshTokenStr)
	if err != nil {
		services.ClearTokensCookies(c)
		status, message := services.MapAuthError(err)
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	services.SetJwtTokensCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Refreshed successfully"}, []string{})
}

func Me(c *gin.Context) {
	id, exists := c.Get("sub")
	if !exists {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	user, err := services.FindUserById(id.(uint))
	if err != nil {
		status, message := services.MapAuthError(err)
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	type UserResponse struct {
		Id       uint   `json:"id"`
		Name     string `json:"name"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Main     bool   `json:"main"`
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"user": UserResponse{
		Id:       user.Id,
		Name:     user.Name,
		Username: user.Username,
		Email:    user.Email,
		Main:     user.Main,
	}}, []string{})
}

func UpdateMe(c *gin.Context) {
	var req validators.UpdateMeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid me-edit request"}, []string{})
		return
	}
	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "User Id not found in context"}, []string{})
		return
	}

	updatedUser, err := services.UpdateUser(userId.(uint), req)
	if err != nil {
		status, message := services.MapAuthError(err)
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	type UserResponse struct {
		Id       uint   `json:"id"`
		Name     string `json:"name"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	utils.SendJSON(c, http.StatusOK, gin.H{
		"message": "Profile updated successfully",
		"user": UserResponse{
			Id:       updatedUser.Id,
			Name:     updatedUser.Name,
			Username: updatedUser.Username,
			Email:    updatedUser.Email,
		},
	}, []string{})
}

func SignOut(c *gin.Context) {
	services.ClearTokensCookies(c)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Sign out successful"}, []string{})
}

func ForgotPassword(c *gin.Context) {
	var req validators.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid forgot-password request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	user, err := services.FindUserByEmail(req.Email)
	if err != nil {
		status, message := services.MapAuthError(err)
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	token, err := services.SetForgotPasswordToken(user)
	if err != nil {
		status, message := services.MapAuthError(err)
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	if err := services.SendPasswordRecoveryEmail(user, token); err != nil {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "Failed to send recovery email"}, []string{})
		return
	}

	utils.SendJSON(c, http.StatusOK, gin.H{
		"message": fmt.Sprintf("Password recovery instructions sent to %s", user.Email),
	}, []string{})
}

func ResetPasswordValidToken(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Token is required"}, []string{})
		return
	}

	isValid, err := services.IsResetPasswordTokenValid(token)
	if err != nil {
		status, message := services.MapAuthError(err)
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	if !isValid {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid or expired token"}, []string{})
		return
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Token is valid"}, []string{})
}

func ResetPasswordChangePassword(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Token is required"}, []string{})
		return
	}

	isValid, err := services.IsResetPasswordTokenValid(token)
	if err != nil {
		status, message := services.MapAuthError(err)
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	if !isValid {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid or expired token"}, []string{})
		return
	}

	var req validators.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid reset-password request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	if err := services.ChangePasswordWithToken(token, req.NewPassword); err != nil {
		status, message := services.MapAuthError(err)
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Password changed successfully"}, []string{})
}

func GetCsrfToken(c *gin.Context) {
	csrfToken, err := services.GenerateCsrfToken()
	if err != nil {
		status, message := services.MapAuthError(err)
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	csrfExpiration := time.Now().Add(15 * time.Minute)
	services.SetCsrfCookie(c, csrfToken, csrfExpiration)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "CSRF token generated successful"}, []string{})
}
