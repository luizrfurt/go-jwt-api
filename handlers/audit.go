// handlers/audit.go
package handlers

import (
	"go-jwt-api/services"
	"go-jwt-api/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func GetAuditLogs(c *gin.Context) {
	contextId, exists := c.Get("ctx")
	if !exists {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "Context not found"}, []string{})
		return
	}
	contextIdUint := contextId.(uint)

	logs, err := services.GetAuditLogs(&contextIdUint)
	if err != nil {
		utils.SendJSONError(c, http.StatusInternalServerError, gin.H{"error": "Failed to retrieve audit logs"}, []string{})
		return
	}

	type AuditLogResponse struct {
		Id         uint      `json:"id"`
		UserId     *uint     `json:"user_id"`
		ContextId  *uint     `json:"context_id"`
		Action     string    `json:"action"`
		Route      string    `json:"route"`
		Method     string    `json:"method"`
		ResourceId *string   `json:"resource_id"`
		IPAddress  string    `json:"ip_address"`
		UserAgent  string    `json:"user_agent"`
		Status     int       `json:"status"`
		Success    bool      `json:"success"`
		Duration   int64     `json:"duration_ms"`
		CreatedAt  time.Time `json:"created_at"`
		UpdatedAt  time.Time `json:"updated_at"`
	}

	var auditResp []AuditLogResponse
	for _, log := range logs {
		auditResp = append(auditResp, AuditLogResponse{
			Id:         log.Id,
			UserId:     log.UserId,
			ContextId:  log.ContextId,
			Action:     log.Action,
			Route:      log.Route,
			Method:     log.Method,
			ResourceId: log.ResourceId,
			IPAddress:  log.IPAddress,
			UserAgent:  log.UserAgent,
			Status:     log.Status,
			Success:    log.Success,
			Duration:   log.Duration,
			CreatedAt:  log.CreatedAt,
			UpdatedAt:  log.UpdatedAt,
		})
	}

	utils.SendJSON(
		c,
		http.StatusOK,
		gin.H{"message": "Audit logs retrieved successfully"},
		auditResp,
	)
}
