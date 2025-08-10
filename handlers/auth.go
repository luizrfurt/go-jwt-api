// handlers/auth.go
package handlers

import (
	"fmt"
	"go-jwt-api/config"
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

	if status, message, _ := services.RegisterUser(req); status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	message := "Registration successful"
	if config.AppConfig.Environment == "production" {
		user, _, _, _ := services.FindUserByEmail(req.Email)
		token, _, _, _ := services.SetEmailVerificationToken(user, false)
		_ = services.SendVerificationEmail(user, token)
		message = message + ", a verification email has been sent to your inbox"
	}
	utils.SendJSON(c, http.StatusCreated, gin.H{"message": message}, []string{})
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

	user, status, message, _ := services.FindUserByEmail(req.Email)
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}
	if config.AppConfig.Environment == "production" && !user.EmailVerified {
		utils.SendJSONError(c, http.StatusUnauthorized, gin.H{"error": "Email not verified, please check your inbox to confirm your email address."}, []string{})
		return
	}

	accessToken, refreshToken, accessExpiration, refreshExpiration, status, message, _ := services.AuthenticateUser(req.Email, req.Password)
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	contexts, _, _, _ := services.GetUserContexts(user.Id)
	selectedContext, _, _, _ := services.GetSelectedContext(user.Id)

	type ContextResponse struct {
		Id          uint   `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Active      bool   `json:"active"`
		IsSelected  bool   `json:"is_selected"`
	}

	var contextResponse []ContextResponse
	for _, ctx := range contexts {
		isSelected := false
		if selectedContext != nil && selectedContext.Id == ctx.Id {
			isSelected = true
		}

		contextResponse = append(contextResponse, ContextResponse{
			Id:          ctx.Id,
			Name:        ctx.Name,
			Description: ctx.Description,
			Active:      ctx.Active,
			IsSelected:  isSelected,
		})
	}

	services.SetJwtTokensCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)
	utils.SendJSON(c, http.StatusOK, gin.H{
		"message":  "Sign in successful",
		"contexts": contextResponse,
	}, []string{})
}

func Refresh(c *gin.Context) {
	refreshTokenStr, err := c.Cookie("session.xrefresh")
	if err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Refresh token not provided"}, []string{})
		return
	}

	accessToken, refreshToken, accessExpiration, refreshExpiration, status, message, err := services.RefreshPair(refreshTokenStr)
	if status != 0 {
		services.ClearTokensCookies(c)
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	services.SetJwtTokensCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Refreshed successfully"}, []string{})
}

func GetMe(c *gin.Context) {
	id, exists := c.Get("sub")
	if !exists {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	user, status, message, _ := services.FindUserById(id.(uint))
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	type UserResponse struct {
		Id            uint   `json:"id"`
		Name          string `json:"name"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Main          bool   `json:"main"`
	}

	userResp := UserResponse{
		Id:            user.Id,
		Name:          user.Name,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Main:          user.Main,
	}

	utils.SendJSON(
		c,
		http.StatusOK,
		gin.H{"message": "User retrieved successfully"},
		[]UserResponse{userResp},
	)
}

func UpdateMe(c *gin.Context) {
	var req validators.UpdateMeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid update me request"}, []string{})
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

	updatedUser, status, message, _ := services.UpdateUser(userId.(uint), req)
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	type UserResponse struct {
		Id            uint   `json:"id"`
		Name          string `json:"name"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Main          bool   `json:"main"`
	}

	userResp := UserResponse{
		Id:            updatedUser.Id,
		Name:          updatedUser.Name,
		Email:         updatedUser.Email,
		EmailVerified: updatedUser.EmailVerified,
		Main:          updatedUser.Main,
	}

	utils.SendJSON(
		c,
		http.StatusOK,
		gin.H{"message": "User updated successfully"},
		[]UserResponse{userResp},
	)
}

func SignOut(c *gin.Context) {
	services.ClearTokensCookies(c)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Sign out successful"}, []string{})
}

func VerifyEmail(c *gin.Context) {
	var req validators.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid verify email request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	user, status, message, _ := services.FindUserByEmail(req.Email)
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	if config.AppConfig.Environment == "production" && !user.EmailVerified {
		token, status, message, _ := services.SetEmailVerificationToken(user, false)
		if status != 0 {
			utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
			return
		}

		if err := services.SendVerificationEmail(user, token); err != nil {
			utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "Failed to send verification email"}, []string{})
			return
		}

		utils.SendJSON(c, http.StatusOK, gin.H{
			"message": fmt.Sprintf("Email verification instructions sent to %s", user.Email),
		}, []string{})
	} else {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Email %s already verified", user.Email)}, []string{})
	}

}

func VerificationEmailValidToken(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Token is required"}, []string{})
		return
	}

	status, message, _ := services.IsVerificationEmailTokenValid(token)
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Email verified successfully"}, []string{})
}

func ForgotPassword(c *gin.Context) {
	var req validators.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid forgot password request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	user, status, message, _ := services.FindUserByEmail(req.Email)
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	token, status, message, _ := services.SetForgotPasswordToken(user)
	if status != 0 {
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

	isValid, status, message, _ := services.IsResetPasswordTokenValid(token)
	if status != 0 {
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

	isValid, status, message, _ := services.IsResetPasswordTokenValid(token)
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	if !isValid {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid or expired token"}, []string{})
		return
	}

	var req validators.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid reset password request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	if status, message, _ := services.ChangePasswordWithToken(token, req.NewPassword); status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Password changed successfully"}, []string{})
}

func GetCsrfToken(c *gin.Context) {
	csrfToken, status, message, _ := services.GenerateCsrfToken()
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	csrfExpiration := time.Now().Add(15 * time.Minute)
	services.SetCsrfCookie(c, csrfToken, csrfExpiration)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "CSRF token generated successful"}, []string{})
}
