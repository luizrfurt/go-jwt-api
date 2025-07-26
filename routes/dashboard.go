// routes/dashboard.go
package routes

import (
	"go-jwt-api/middlewares"

	"github.com/gin-gonic/gin"
)

func RegisterDashboardRoutes(r *gin.Engine) {
	dashboardGroup := r.Group("/dashboard")
	dashboardGroup.Use(middlewares.AuthMiddleware())
	{
		dashboardGroup.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "Welcome to your dashboard!"})
		})
		// dashboardGroup.GET("/stats", getDashboardStats)
		// dashboardGroup.GET("/recent", getRecentActivity)
	}
}
