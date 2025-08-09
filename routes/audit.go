// routes/audit.go
package routes

import (
	"go-jwt-api/handlers"
	"go-jwt-api/middlewares"

	"github.com/gin-gonic/gin"
)

func RegisterAuditRoutes(r *gin.Engine) {
	auditGroup := r.Group("/audit")
	auditGroup.Use(middlewares.AuthMiddleware(), middlewares.CSRFMiddleware())
	{
		auditGroup.GET("/logs", handlers.GetAuditLogs)
	}
}
