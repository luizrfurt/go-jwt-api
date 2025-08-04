// handlers/context.go
package handlers

import (
	"go-jwt-api/services"
	"go-jwt-api/utils"
	"go-jwt-api/validators"
	"net/http"

	"github.com/gin-gonic/gin"
)

func GetMyContexts(c *gin.Context) {
	userId, exists := c.Get("sub")
	if !exists {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	contexts, status, message, _ := services.GetUserContexts(userId.(uint))
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	activeContext, _, _, _ := services.GetActiveContext(userId.(uint))

	type ContextResponse struct {
		Id          uint   `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		IsActive    bool   `json:"is_active"`
	}

	var response []ContextResponse
	for _, ctx := range contexts {
		isActive := false
		if activeContext != nil && activeContext.Id == ctx.Id {
			isActive = true
		}

		response = append(response, ContextResponse{
			Id:          ctx.Id,
			Name:        ctx.Name,
			Description: ctx.Description,
			IsActive:    isActive,
		})
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Contexts retrieved successfully"}, response)
}

func CreateContext(c *gin.Context) {
	var req validators.CreateContextRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid create context request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	context, status, message, _ := services.CreateContext(userId.(uint), req)
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	type ContextResponse struct {
		Id          uint   `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	utils.SendJSON(c, http.StatusCreated, gin.H{"message": "Context created successfully"}, ContextResponse{
		Id:          context.Id,
		Name:        context.Name,
		Description: context.Description,
	})
}

func SelectContext(c *gin.Context) {
	var req validators.SelectContextRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid select context request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	status, message, _ := services.SelectContext(userId.(uint), req.ContextId)
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	activeContext, _, _, _ := services.GetActiveContext(userId.(uint))
	var contextId uint
	if activeContext != nil {
		contextId = activeContext.Id
	}

	accessToken, refreshToken, accessExpiration, refreshExpiration, status, message, _ := services.GenerateTokensWithContext(userId.(uint), contextId)
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	services.SetJwtTokensCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Context selected successfully"}, []string{})
}

func GetActiveContext(c *gin.Context) {
	userId, exists := c.Get("sub")
	if !exists {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	context, status, message, _ := services.GetActiveContext(userId.(uint))
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	type ContextResponse struct {
		Id          uint   `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Active context retrieved successfully"}, ContextResponse{
		Id:          context.Id,
		Name:        context.Name,
		Description: context.Description,
	})
}
