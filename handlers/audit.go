// handlers/audit.go
package handlers

import (
	"go-jwt-api/models"
	"go-jwt-api/services"
	"go-jwt-api/utils"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func GetAuditLogs(c *gin.Context) {
	userIdStr := c.Query("user_id")
	contextIdStr := c.Query("context_id")
	action := c.Query("action")
	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")

	var userId, contextId *uint

	if userIdStr != "" {
		if id, err := strconv.ParseUint(userIdStr, 10, 32); err == nil {
			uid := uint(id)
			userId = &uid
		}
	}

	if contextIdStr != "" {
		if id, err := strconv.ParseUint(contextIdStr, 10, 32); err == nil {
			cid := uint(id)
			contextId = &cid
		}
	}

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	if limit > 100 {
		limit = 100
	}

	logs, total, err := services.GetAuditLogs(userId, contextId, action, limit, offset)
	if err != nil {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit logs"}, []string{})
		return
	}

	type AuditResponse struct {
		Logs   []models.AuditLog `json:"logs"`
		Total  int               `json:"total"`
		Limit  int               `json:"limit"`
		Offset int               `json:"offset"`
	}

	response := AuditResponse{
		Logs:   logs,
		Total:  int(total),
		Limit:  limit,
		Offset: offset,
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Audit logs retrieved successfully"}, []AuditResponse{response})
}
