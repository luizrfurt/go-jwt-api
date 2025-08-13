// handlers/context.go
package handlers

import (
	"go-jwt-api/middlewares"
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
		middlewares.SetAuditData(c, "context_list_view_failed", nil, nil, map[string]interface{}{
			"reason": "user_not_in_context",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	contexts, status, message, _ := services.GetUserContexts(userId.(uint))
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "context_list_view_failed", &userIdStr, nil, map[string]interface{}{
			"user_id": userId.(uint),
			"reason":  "service_error",
			"error":   message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
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

	userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
	var selectedContextId *uint
	if selectedContext != nil {
		selectedContextId = &selectedContext.Id
	}

	middlewares.SetAuditData(c, "context_list_view_success", &userIdStr, nil, map[string]interface{}{
		"user_id":          userId.(uint),
		"contexts_count":   len(response),
		"selected_context": selectedContextId,
	})

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Contexts retrieved successfully"}, response)
}

func CreateContext(c *gin.Context) {
	var req validators.CreateContextRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "context_create_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id": userId.(uint),
				"reason":  "invalid_json",
				"error":   err.Error(),
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid create context request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "context_create_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id":           userId.(uint),
				"name":              req.Name,
				"description":       req.Description,
				"reason":            "validation_failed",
				"validation_errors": validationErrors,
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		middlewares.SetAuditData(c, "context_create_failed", nil, nil, map[string]interface{}{
			"reason": "user_not_in_context",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	context, status, message, _ := services.CreateContext(userId.(uint), req)
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "context_create_failed", &userIdStr, nil, map[string]interface{}{
			"user_id":     userId.(uint),
			"name":        req.Name,
			"description": req.Description,
			"reason":      "service_error",
			"error":       message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
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

	userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
	middlewares.SetAuditData(c, "context_create_success", &userIdStr, nil, map[string]interface{}{
		"user_id":     userId.(uint),
		"context_id":  context.Id,
		"name":        context.Name,
		"description": context.Description,
		"active":      context.Active,
	})

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
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "context_update_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id":    userId.(uint),
				"context_id": contextIdStr,
				"reason":     "invalid_context_id",
				"error":      err.Error(),
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid context ID"}, []string{})
		return
	}

	var req validators.UpdateContextRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "context_update_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id":    userId.(uint),
				"context_id": uint(contextId),
				"reason":     "invalid_json",
				"error":      err.Error(),
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid update context request"}, []string{})
		return
	}

	if validationErrors := validators.ValidateStruct(req); validationErrors != nil {
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "context_update_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id":           userId.(uint),
				"context_id":        uint(contextId),
				"name":              req.Name,
				"description":       req.Description,
				"reason":            "validation_failed",
				"validation_errors": validationErrors,
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"validation_errors": validationErrors}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		middlewares.SetAuditData(c, "context_update_failed", nil, nil, map[string]interface{}{
			"context_id": uint(contextId),
			"reason":     "user_not_in_context",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	oldContext, _, _, _ := services.GetContextById(uint(contextId))
	var oldValues interface{}
	if oldContext != nil {
		oldValues = map[string]interface{}{
			"name":        oldContext.Name,
			"description": oldContext.Description,
		}
	}

	context, status, message, _ := services.UpdateContext(userId.(uint), uint(contextId), req)
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "context_update_failed", &userIdStr, oldValues, map[string]interface{}{
			"user_id":     userId.(uint),
			"context_id":  uint(contextId),
			"name":        req.Name,
			"description": req.Description,
			"reason":      "service_error",
			"error":       message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
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

	userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
	newValues := map[string]interface{}{
		"name":        req.Name,
		"description": req.Description,
	}
	middlewares.SetAuditData(c, "context_update_success", &userIdStr, oldValues, newValues)

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
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "context_activate_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id":    userId.(uint),
				"context_id": contextIdStr,
				"reason":     "invalid_context_id",
				"error":      err.Error(),
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid context ID"}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		middlewares.SetAuditData(c, "context_activate_failed", nil, nil, map[string]interface{}{
			"context_id": uint(contextId),
			"reason":     "user_not_in_context",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	status, message, _ := services.ActivateContext(userId.(uint), uint(contextId))
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "context_activate_failed", &userIdStr, nil, map[string]interface{}{
			"user_id":    userId.(uint),
			"context_id": uint(contextId),
			"reason":     "service_error",
			"error":      message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
	middlewares.SetAuditData(c, "context_activate_success", &userIdStr, nil, map[string]interface{}{
		"user_id":    userId.(uint),
		"context_id": uint(contextId),
	})

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Context activated successfully"}, []string{})
}

func DeactivateContext(c *gin.Context) {
	contextIdStr := c.Param("id")
	contextId, err := strconv.ParseUint(contextIdStr, 10, 32)
	if err != nil {
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "context_deactivate_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id":    userId.(uint),
				"context_id": contextIdStr,
				"reason":     "invalid_context_id",
				"error":      err.Error(),
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid context ID"}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		middlewares.SetAuditData(c, "context_deactivate_failed", nil, nil, map[string]interface{}{
			"context_id": uint(contextId),
			"reason":     "user_not_in_context",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	status, message, _ := services.DeactivateContext(userId.(uint), uint(contextId))
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "context_deactivate_failed", &userIdStr, nil, map[string]interface{}{
			"user_id":    userId.(uint),
			"context_id": uint(contextId),
			"reason":     "service_error",
			"error":      message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
	middlewares.SetAuditData(c, "context_deactivate_success", &userIdStr, nil, map[string]interface{}{
		"user_id":    userId.(uint),
		"context_id": uint(contextId),
	})

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Context deactivated successfully"}, []string{})
}

func DeleteContext(c *gin.Context) {
	contextIdStr := c.Param("id")
	contextId, err := strconv.ParseUint(contextIdStr, 10, 32)
	if err != nil {
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "context_delete_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id":    userId.(uint),
				"context_id": contextIdStr,
				"reason":     "invalid_context_id",
				"error":      err.Error(),
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid context ID"}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		middlewares.SetAuditData(c, "context_delete_failed", nil, nil, map[string]interface{}{
			"context_id": uint(contextId),
			"reason":     "user_not_in_context",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	contextToDelete, _, _, _ := services.GetContextById(uint(contextId))
	var oldValues interface{}
	if contextToDelete != nil {
		oldValues = map[string]interface{}{
			"name":        contextToDelete.Name,
			"description": contextToDelete.Description,
			"active":      contextToDelete.Active,
			"owner_id":    contextToDelete.OwnerId,
		}
	}

	status, message, _ := services.DeleteContext(userId.(uint), uint(contextId))
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "context_delete_failed", &userIdStr, oldValues, map[string]interface{}{
			"user_id":    userId.(uint),
			"context_id": uint(contextId),
			"reason":     "service_error",
			"error":      message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
	middlewares.SetAuditData(c, "context_delete_success", &userIdStr, oldValues, map[string]interface{}{
		"user_id":    userId.(uint),
		"context_id": uint(contextId),
	})

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Context deleted successfully"}, []string{})
}

func GetSelectedContext(c *gin.Context) {
	userId, exists := c.Get("sub")
	if !exists {
		middlewares.SetAuditData(c, "selected_context_view_failed", nil, nil, map[string]interface{}{
			"reason": "user_not_in_context",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	context, status, message, _ := services.GetSelectedContext(userId.(uint))
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "selected_context_view_failed", &userIdStr, nil, map[string]interface{}{
			"user_id": userId.(uint),
			"reason":  "service_error",
			"error":   message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
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

	userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
	middlewares.SetAuditData(c, "selected_context_view_success", &userIdStr, nil, map[string]interface{}{
		"user_id":    userId.(uint),
		"context_id": context.Id,
		"name":       context.Name,
		"active":     context.Active,
	})

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
		userId, exists := c.Get("sub")
		if exists {
			userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
			middlewares.SetAuditData(c, "context_select_attempt", &userIdStr, nil, map[string]interface{}{
				"user_id":    userId.(uint),
				"context_id": contextIdStr,
				"reason":     "invalid_context_id",
				"error":      err.Error(),
			})
		}

		utils.SendJSON(c, http.StatusBadRequest, gin.H{"error": "Invalid context ID"}, []string{})
		return
	}

	userId, exists := c.Get("sub")
	if !exists {
		middlewares.SetAuditData(c, "context_select_failed", nil, nil, map[string]interface{}{
			"context_id": uint(idSelect),
			"reason":     "user_not_in_context",
		})

		utils.SendJSON(c, http.StatusInternalServerError, gin.H{"error": "User not found in context"}, []string{})
		return
	}

	oldSelectedContext, _, _, _ := services.GetSelectedContext(userId.(uint))
	var oldValues interface{}
	if oldSelectedContext != nil {
		oldValues = map[string]interface{}{
			"selected_context_id":   oldSelectedContext.Id,
			"selected_context_name": oldSelectedContext.Name,
		}
	}

	status, message, _ := services.SelectContext(userId.(uint), uint(idSelect))
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "context_select_failed", &userIdStr, oldValues, map[string]interface{}{
			"user_id":    userId.(uint),
			"context_id": uint(idSelect),
			"reason":     "service_error",
			"error":      message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	selectedContext, _, _, _ := services.GetSelectedContext(userId.(uint))
	var contextId uint
	if selectedContext != nil {
		contextId = selectedContext.Id
	}

	accessToken, refreshToken, accessExpiration, refreshExpiration, status, message, _ := services.GenerateTokensWithContext(userId.(uint), contextId)
	if status != 0 {
		userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
		middlewares.SetAuditData(c, "context_select_failed", &userIdStr, oldValues, map[string]interface{}{
			"user_id":    userId.(uint),
			"context_id": uint(idSelect),
			"reason":     "token_generation_error",
			"error":      message,
		})

		utils.SendJSON(c, status, gin.H{"error": message}, []string{})
		return
	}

	userIdStr := strconv.FormatUint(uint64(userId.(uint)), 10)
	newValues := map[string]interface{}{
		"new_selected_context_id": uint(idSelect),
		"token_expires_at":        accessExpiration.Format(time.RFC3339),
	}
	if selectedContext != nil {
		newValues["new_selected_context_name"] = selectedContext.Name
	}

	middlewares.SetAuditData(c, "context_select_success", &userIdStr, oldValues, newValues)

	services.SetJwtTokensCookies(c, accessToken, refreshToken, accessExpiration, refreshExpiration)
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Context selected successfully"}, []string{})
}
