// handlers/context.go
package handlers

import (
	"go-jwt-api/services"
	"go-jwt-api/utils"
	"go-jwt-api/validators"
	"net/http"
	"strconv"
	"time"

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

	selectedContext, _, _, _ := services.GetSelectedContext(userId.(uint))

	type ContextResponse struct {
		Id          uint      `json:"id"`
		Name        string    `json:"name"`
		Description string    `json:"description"`
		Active      bool      `json:"active"`
		IsSelected  bool      `json:"is_selected"`
		CreatedAt   time.Time `json:"created_at"`
	}

	var response []ContextResponse
	for _, ctx := range contexts {
		isSelected := false
		if selectedContext != nil && selectedContext.Id == ctx.Id {
			isSelected = true
		}

		response = append(response, ContextResponse{
			Id:          ctx.Id,
			Name:        ctx.Name,
			Description: ctx.Description,
			Active:      ctx.Active,
			IsSelected:  isSelected,
			CreatedAt:   ctx.CreatedAt,
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
		Id          uint      `json:"id"`
		Name        string    `json:"name"`
		Description string    `json:"description"`
		Active      bool      `json:"active"`
		CreatedAt   time.Time `json:"created_at"`
	}

	createdResp := ContextResponse{
		Id:          context.Id,
		Name:        context.Name,
		Description: context.Description,
		Active:      context.Active,
		CreatedAt:   context.CreatedAt,
	}

	utils.SendJSON(
		c,
		http.StatusCreated,
		gin.H{"message": "Context created successfully"},
		[]ContextResponse{createdResp},
	)
}

func UpdateContext(c *gin.Context) {
	contextIdStr := c.Param("id")
	contextId, err := strconv.ParseUint(contextIdStr, 10, 32)
	if err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid context ID"}, []string{})
		return
	}

	var req validators.UpdateContextRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid update context request"}, []string{})
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

	context, status, message, _ := services.UpdateContext(userId.(uint), uint(contextId), req)
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	type ContextResponse struct {
		Id          uint   `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Active      bool   `json:"active"`
	}

	updatedResp := ContextResponse{
		Id:          context.Id,
		Name:        context.Name,
		Description: context.Description,
		Active:      context.Active,
	}

	utils.SendJSON(
		c,
		http.StatusOK,
		gin.H{"message": "Context updated successfully"},
		[]ContextResponse{updatedResp},
	)
}

func ActivateContext(c *gin.Context) {
	contextIdStr := c.Param("id")
	contextId, err := strconv.ParseUint(contextIdStr, 10, 32)
	if err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid context ID"}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	status, message, _ := services.ActivateContext(userId.(uint), uint(contextId))
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Context activated successfully"}, []string{})
}

func DeactivateContext(c *gin.Context) {
	contextIdStr := c.Param("id")
	contextId, err := strconv.ParseUint(contextIdStr, 10, 32)
	if err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid context ID"}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	status, message, _ := services.DeactivateContext(userId.(uint), uint(contextId))
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Context deactivated successfully"}, []string{})
}

func DeleteContext(c *gin.Context) {
	contextIdStr := c.Param("id")
	contextId, err := strconv.ParseUint(contextIdStr, 10, 32)
	if err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid context ID"}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	status, message, _ := services.DeleteContext(userId.(uint), uint(contextId))
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Context deleted successfully"}, []string{})
}

func GetSelectedContext(c *gin.Context) {
	userId, exists := c.Get("sub")
	if !exists {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	context, status, message, _ := services.GetSelectedContext(userId.(uint))
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	type ContextResponse struct {
		Id          uint   `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Active      bool   `json:"active"`
	}

	selectedResp := ContextResponse{
		Id:          context.Id,
		Name:        context.Name,
		Description: context.Description,
		Active:      context.Active,
	}

	utils.SendJSON(
		c,
		http.StatusOK,
		gin.H{"message": "Selected context retrieved successfully"},
		[]ContextResponse{selectedResp},
	)
}

func SelectContext(c *gin.Context) {
	contextIdStr := c.Param("id")
	idSelect, err := strconv.ParseUint(contextIdStr, 10, 32)
	if err != nil {
		utils.SendJSONError(c, http.StatusBadRequest, gin.H{"error": "Invalid context ID"}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	status, message, _ := services.SelectContext(userId.(uint), uint(idSelect))
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	selectedContext, _, _, _ := services.GetSelectedContext(userId.(uint))
	var contextId uint
	if selectedContext != nil {
		contextId = selectedContext.Id
	}

	accessToken, refreshToken, accessExpiration, refreshExpiration, status, message, _ := services.GenerateTokensWithContext(userId.(uint), contextId)
	if status != 0 {
		utils.SendJSONError(c, status, gin.H{"error": message}, []string{})
		return
	}

	services.SetJwtTokensCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Context selected successfully"}, []string{})
}
