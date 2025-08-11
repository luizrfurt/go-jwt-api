// handlers/audit.go
package handlers

import (
	"go-jwt-api/models"
	"go-jwt-api/services"
	"go-jwt-api/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

func GetAuditLogs(c *gin.Context) {
	userId, exists := c.Get("sub")
	if !exists {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "User Id not found in context"}, []string{})
		return
	}
	userIdUint := userId.(uint)

	logs, total, err := services.GetAuditLogs(&userIdUint)
	if err != nil {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit logs"}, []string{})
		return
	}

	type AuditResponse struct {
		Logs  []models.AuditLog `json:"logs"`
		Total int               `json:"total"`
	}

	response := AuditResponse{
		Logs:  logs,
		Total: int(total),
	}

	utils.SendJSON(c, http.StatusOK, gin.H{"message": "Audit logs retrieved successfully"}, []AuditResponse{response})
}
