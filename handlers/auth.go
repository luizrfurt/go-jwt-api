// handlers/auth.go
package handlers

import (
	"fmt"
	"go-jwt-api/config"
	"go-jwt-api/middlewares"
	"go-jwt-api/services"
	"go-jwt-api/utils"
	"go-jwt-api/validators"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

func SignUp(c *gin.Context) {
	var req validators.SignUpRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middlewares.SetAuditData(c, "user_signup_attempt", nil, nil, map[string]interface{}{
			"email":  "invalid_request",
			"reason": "invalid_json",
			"error":  err.Error(),
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid signup request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		middlewares.SetAuditData(c, "user_signup_attempt", nil, nil, map[string]interface{}{
			"email":             req.Email,
			"name":              req.Name,
			"reason":            "validation_failed",
			"validation_errors": validationErrors,
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	if status, message, _ := services.RegisterUser(req); status != 0 {
		middlewares.SetAuditData(c, "user_signup_failed", nil, nil, map[string]interface{}{
			"email":  req.Email,
			"name":   req.Name,
			"reason": "registration_failed",
			"error":  message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	message := "Registration successful"
	auditData := map[string]interface{}{
		"email": req.Email,
		"name":  req.Name,
	}

	if config.AppConfig.Environment == "production" {
		user, _, _, _ := services.FindUserByEmail(req.Email)
		token, _, _, _ := services.SetEmailVerificationToken(user, false)
		_ = services.SendVerificationEmail(user, token)
		message = message + ", a verification email has been sent to your inbox"
		auditData["email_verification_sent"] = true
	} else {
		auditData["email_verified_automatically"] = true
	}

	middlewares.SetAuditData(c, "user_signup_success", nil, nil, auditData)
	utils.SendJSON(c, http.StatusCreated, gin.H{"message": message}, []string{})
}

func SignIn(c *gin.Context) {
	var req validators.SignInRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middlewares.SetAuditData(c, "user_login_attempt", nil, nil, map[string]interface{}{
			"email":  "invalid_request",
			"reason": "invalid_json",
			"error":  err.Error(),
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid signin request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		middlewares.SetAuditData(c, "user_login_attempt", nil, nil, map[string]interface{}{
			"email":             req.Email,
			"reason":            "validation_failed",
			"validation_errors": validationErrors,
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	user, status, message, _ := services.FindUserByEmail(req.Email)
	if status != 0 {
		middlewares.SetAuditData(c, "user_login_failed", nil, nil, map[string]interface{}{
			"email":  req.Email,
			"reason": "user_not_found",
			"error":  message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	if config.AppConfig.Environment == "production" && !user.EmailVerified {
		userIdStr := strconv.FormatUint(uint64(user.Id), 10)
		middlewares.SetAuditData(c, "user_login_failed", &userIdStr, nil, map[string]interface{}{
			"email":   req.Email,
			"reason":  "email_not_verified",
			"user_id": user.Id,
		})

		utils.SendJSON(c, http.StatusUnauthorized, gin.H{"error": "Email not verified, please check your inbox to confirm your email address."}, []string{})
		return
	}

	accessToken, refreshToken, accessExpiration, refreshExpiration, status, message, _ := services.AuthenticateUser(req.Email, req.Password)
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(user.Id), 10)
		middlewares.SetAuditData(c, "user_login_failed", &userIdStr, nil, map[string]interface{}{
			"email":   req.Email,
			"reason":  "invalid_credentials",
			"user_id": user.Id,
			"error":   message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
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

	userIdStr := strconv.FormatUint(uint64(user.Id), 10)
	var selectedContextId *uint
	if selectedContext != nil {
		selectedContextId = &selectedContext.Id
	}

	middlewares.SetAuditData(c, "user_login_success", &userIdStr, nil, map[string]interface{}{
		"email":            req.Email,
		"user_id":          user.Id,
		"user_name":        user.Name,
		"selected_context": selectedContextId,
		"contexts_count":   len(contextResponse),
		"email_verified":   user.EmailVerified,
		"token_expires_at": accessExpiration.Format(time.RFC3339),
	})

	services.SetJwtTokensCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)
	utils.SendJSON(c, http.StatusOK, gin.H{
		"message":  "Sign in successful",
		"contexts": contextResponse,
	}, []string{})
}

func Refresh(c *gin.Context) {
	refreshTokenStr, err := c.Cookie("session.xrefresh")
	if err != nil {
		middlewares.SetAuditData(c, "token_refresh_failed", nil, nil, map[string]interface{}{
			"reason": "refresh_token_not_provided",
			"error":  err.Error(),
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Refresh token not provided"}, []string{})
		return
	}

	accessToken, refreshToken, accessExpiration, refreshExpiration, status, message, err := services.RefreshPair(refreshTokenStr)
	if status != 0 {
		middlewares.SetAuditData(c, "token_refresh_failed", nil, nil, map[string]interface{}{
			"reason": "invalid_refresh_token",
			"error":  message,
		})

		services.ClearTokensCookies(c)
		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	var userId *uint
	if claims, _, _, _ := services.ValidateAccessToken(accessToken); claims != nil {
		userId = &claims.Sub
		userIdStr := strconv.FormatUint(uint64(*userId), 10)
		middlewares.SetAuditData(c, "token_refresh_success", &userIdStr, nil, map[string]interface{}{
			"user_id":          *userId,
			"token_expires_at": accessExpiration.Format(time.RFC3339),
		})
	} else {
		middlewares.SetAuditData(c, "token_refresh_success", nil, nil, map[string]interface{}{
			"token_expires_at": accessExpiration.Format(time.RFC3339),
		})
	}

	services.SetJwtTokensCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Refreshed successfully"}, []string{})
}

func GetMe(c *gin.Context) {
	id, exists := c.Get("sub")
	if !exists {
		middlewares.SetAuditData(c, "user_profile_view_failed", nil, nil, map[string]interface{}{
			"reason": "user_not_in_context",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	user, status, message, _ := services.FindUserById(id.(uint))
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(id.(uint)), 10)
		middlewares.SetAuditData(c, "user_profile_view_failed", &userIdStr, nil, map[string]interface{}{
			"user_id": id.(uint),
			"reason":  "user_not_found",
			"error":   message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
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

	userIdStr := strconv.FormatUint(uint64(user.Id), 10)
	middlewares.SetAuditData(c, "user_profile_view_success", &userIdStr, nil, map[string]interface{}{
		"user_id":        user.Id,
		"email":          user.Email,
		"email_verified": user.EmailVerified,
	})

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
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "user_update_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id": userId.(uint),
				"reason":  "invalid_json",
				"error":   err.Error(),
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid update me request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "user_update_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id":           userId.(uint),
				"reason":            "validation_failed",
				"validation_errors": validationErrors,
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		middlewares.SetAuditData(c, "user_update_failed", nil, nil, map[string]interface{}{
			"reason": "user_not_in_context",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "User Id not found in context"}, []string{})
		return
	}

	oldUser, _, _, _ := services.FindUserById(userId.(uint))
	var oldValues interface{}
	if oldUser != nil {
		oldValues = map[string]interface{}{
			"name":  oldUser.Name,
			"email": oldUser.Email,
		}
	}

	updatedUser, status, message, _ := services.UpdateUser(userId.(uint), req)
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "user_update_failed", &userIdStr, oldValues, map[string]interface{}{
			"user_id": userId.(uint),
			"name":    req.Name,
			"email":   req.Email,
			"reason":  "update_failed",
			"error":   message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
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

	userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
	newValues := map[string]interface{}{
		"name":  req.Name,
		"email": req.Email,
	}
	if req.NewPassword != nil && *req.NewPassword != "" {
		newValues["password_changed"] = true
	}

	middlewares.SetAuditData(c, "user_update_success", &userIdStr, oldValues, newValues)

	utils.SendJSON(
		c,
		http.StatusOK,
		gin.H{"message": "User updated successfully"},
		[]UserResponse{userResp},
	)
}

func SignOut(c *gin.Context) {
	userId, exists := c.Get("sub")
	if exists {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "user_logout_success", &userIdStr, nil, map[string]interface{}{
			"user_id": userId.(uint),
		})
	} else {
		middlewares.SetAuditData(c, "user_logout_success", nil, nil, map[string]interface{}{
			"anonymous_logout": true,
		})
	}

	services.ClearTokensCookies(c)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Sign out successful"}, []string{})
}

func VerifyEmail(c *gin.Context) {
	var req validators.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middlewares.SetAuditData(c, "email_verification_request_attempt", nil, nil, map[string]interface{}{
			"email":  "invalid_request",
			"reason": "invalid_json",
			"error":  err.Error(),
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid verify email request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		middlewares.SetAuditData(c, "email_verification_request_attempt", nil, nil, map[string]interface{}{
			"email":             req.Email,
			"reason":            "validation_failed",
			"validation_errors": validationErrors,
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	user, status, message, _ := services.FindUserByEmail(req.Email)
	if status != 0 {
		middlewares.SetAuditData(c, "email_verification_request_failed", nil, nil, map[string]interface{}{
			"email":  req.Email,
			"reason": "user_not_found",
			"error":  message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	if config.AppConfig.Environment == "production" && !user.EmailVerified {
		token, status, message, _ := services.SetEmailVerificationToken(user, false)
		if status != 0 {
			userIdStr := strconv.FormatUint(uint64(user.Id), 10)
			middlewares.SetAuditData(c, "email_verification_request_failed", &userIdStr, nil, map[string]interface{}{
				"email":   req.Email,
				"user_id": user.Id,
				"reason":  "token_generation_failed",
				"error":   message,
			})

			utils.SendJSON(c, status, gin.H{"error": message}, []string{})
			return
		}

		if err := services.SendVerificationEmail(user, token); err != nil {
			userIdStr := strconv.FormatUint(uint64(user.Id), 10)
			middlewares.SetAuditData(c, "email_verification_request_failed", &userIdStr, nil, map[string]interface{}{
				"email":   req.Email,
				"user_id": user.Id,
				"reason":  "email_send_failed",
				"error":   err.Error(),
			})

			utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "Failed to send verification email"}, []string{})
			return
		}

		userIdStr := strconv.FormatUint(uint64(user.Id), 10)
		middlewares.SetAuditData(c, "email_verification_request_success", &userIdStr, nil, map[string]interface{}{
			"email":   req.Email,
			"user_id": user.Id,
		})

		utils.SendJSON(c, http.StatusOK, gin.H{
			"message": fmt.Sprintf("Email verification instructions sent to %s", user.Email),
		}, []string{})
	} else {
		userIdStr := strconv.FormatUint(uint64(user.Id), 10)
		middlewares.SetAuditData(c, "email_verification_request_failed", &userIdStr, nil, map[string]interface{}{
			"email":   req.Email,
			"user_id": user.Id,
			"reason":  "email_already_verified",
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Email %s already verified", user.Email)}, []string{})
	}
}

func VerificationEmailValidToken(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		middlewares.SetAuditData(c, "email_verification_attempt", nil, nil, map[string]interface{}{
			"reason": "token_not_provided",
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Token is required"}, []string{})
		return
	}

	status, message, _ := services.IsVerificationEmailTokenValid(token)
	if status != 0 {
		middlewares.SetAuditData(c, "email_verification_failed", nil, nil, map[string]interface{}{
			"token":  token[:10] + "...",
			"reason": "invalid_token",
			"error":  message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	middlewares.SetAuditData(c, "email_verification_success", nil, nil, map[string]interface{}{
		"token": token[:10] + "...",
	})

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Email verified successfully"}, []string{})
}

func ForgotPassword(c *gin.Context) {
	var req validators.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middlewares.SetAuditData(c, "forgot_password_request_attempt", nil, nil, map[string]interface{}{
			"email":  "invalid_request",
			"reason": "invalid_json",
			"error":  err.Error(),
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid forgot password request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		middlewares.SetAuditData(c, "forgot_password_request_attempt", nil, nil, map[string]interface{}{
			"email":             req.Email,
			"reason":            "validation_failed",
			"validation_errors": validationErrors,
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	user, status, message, _ := services.FindUserByEmail(req.Email)
	if status != 0 {
		middlewares.SetAuditData(c, "forgot_password_request_failed", nil, nil, map[string]interface{}{
			"email":  req.Email,
			"reason": "user_not_found",
			"error":  message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	token, status, message, _ := services.SetForgotPasswordToken(user)
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(user.Id), 10)
		middlewares.SetAuditData(c, "forgot_password_request_failed", &userIdStr, nil, map[string]interface{}{
			"email":   req.Email,
			"user_id": user.Id,
			"reason":  "token_generation_failed",
			"error":   message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	if err := services.SendPasswordRecoveryEmail(user, token); err != nil {
		userIdStr := strconv.FormatUint(uint64(user.Id), 10)
		middlewares.SetAuditData(c, "forgot_password_request_failed", &userIdStr, nil, map[string]interface{}{
			"email":   req.Email,
			"user_id": user.Id,
			"reason":  "email_send_failed",
			"error":   err.Error(),
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "Failed to send recovery email"}, []string{})
		return
	}

	userIdStr := strconv.FormatUint(uint64(user.Id), 10)
	middlewares.SetAuditData(c, "forgot_password_request_success", &userIdStr, nil, map[string]interface{}{
		"email":   req.Email,
		"user_id": user.Id,
	})

	utils.SendJSON(c, http.StatusOK, gin.H{
		"message": fmt.Sprintf("Password recovery instructions sent to %s", user.Email),
	}, []string{})
}

func ResetPasswordValidToken(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		middlewares.SetAuditData(c, "reset_password_token_validation_attempt", nil, nil, map[string]interface{}{
			"reason": "token_not_provided",
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Token is required"}, []string{})
		return
	}

	isValid, status, message, _ := services.IsResetPasswordTokenValid(token)
	if status != 0 {
		middlewares.SetAuditData(c, "reset_password_token_validation_failed", nil, nil, map[string]interface{}{
			"token":  token[:10] + "...",
			"reason": "validation_error",
			"error":  message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	if !isValid {
		middlewares.SetAuditData(c, "reset_password_token_validation_failed", nil, nil, map[string]interface{}{
			"token":  token[:10] + "...",
			"reason": "invalid_or_expired_token",
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid or expired token"}, []string{})
		return
	}

	middlewares.SetAuditData(c, "reset_password_token_validation_success", nil, nil, map[string]interface{}{
		"token": token[:10] + "...",
	})

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Token is valid"}, []string{})
}

func ResetPasswordChangePassword(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		middlewares.SetAuditData(c, "reset_password_attempt", nil, nil, map[string]interface{}{
			"reason": "token_not_provided",
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Token is required"}, []string{})
		return
	}

	isValid, status, message, _ := services.IsResetPasswordTokenValid(token)
	if status != 0 {
		middlewares.SetAuditData(c, "reset_password_failed", nil, nil, map[string]interface{}{
			"token":  token[:10] + "...",
			"reason": "token_validation_error",
			"error":  message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	if !isValid {
		middlewares.SetAuditData(c, "reset_password_failed", nil, nil, map[string]interface{}{
			"token":  token[:10] + "...",
			"reason": "invalid_or_expired_token",
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid or expired token"}, []string{})
		return
	}

	var req validators.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middlewares.SetAuditData(c, "reset_password_failed", nil, nil, map[string]interface{}{
			"token":  token[:10] + "...",
			"reason": "invalid_json",
			"error":  err.Error(),
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid reset password request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		middlewares.SetAuditData(c, "reset_password_failed", nil, nil, map[string]interface{}{
			"token":             token[:10] + "...",
			"reason":            "validation_failed",
			"validation_errors": validationErrors,
		})

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	if status, message, _ := services.ChangePasswordWithToken(token, req.NewPassword); status != 0 {
		middlewares.SetAuditData(c, "reset_password_failed", nil, nil, map[string]interface{}{
			"token":  token[:10] + "...",
			"reason": "password_change_failed",
			"error":  message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	middlewares.SetAuditData(c, "reset_password_success", nil, nil, map[string]interface{}{
		"token": token[:10] + "...",
	})

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Password changed successfully"}, []string{})
}

func GetCsrfToken(c *gin.Context) {
	csrfToken, status, message, _ := services.GenerateCsrfToken()
	if status != 0 {
		middlewares.SetAuditData(c, "csrf_token_generation_failed", nil, nil, map[string]interface{}{
			"reason": "token_generation_error",
			"error":  message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if exists {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "csrf_token_generation_success", &userIdStr, nil, map[string]interface{}{
			"user_id": userId.(uint),
		})
	} else {
		middlewares.SetAuditData(c, "csrf_token_generation_success", nil, nil, map[string]interface{}{
			"anonymous_request": true,
		})
	}

	csrfExpiration := time.Now().Add(15 * time.Minute)
	services.SetCsrfCookie(c, csrfToken, csrfExpiration)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "CSRF token generated successful"}, []string{})
}
