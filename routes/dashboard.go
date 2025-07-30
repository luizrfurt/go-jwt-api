// routes/dashboard.go
package routes

import (
	"go-jwt-api/middlewares"
	"go-jwt-api/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

func RegisterDashboardRoutes(r *gin.Engine) {
	dashboardGroup := r.Group("/dashboard")
	dashboardGroup.Use(middlewares.AuthMiddleware())
	{
		dashboardGroup.GET("/", func(c *gin.Context) {
			utils.SendJSON(c, http.StatusOK, gin.H{"message": "Welcome to your dashboard!"}, []string{})
		})
	}
}
