// routes/router.go
package routes

import (
	"go-jwt-api/middlewares"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine) {
	RegisterAuthRoutes(r)

	appGroup := r.Group("/")
	appGroup.Use(middlewares.AuthMiddleware())
	{
		appGroup.GET("/dashboard", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "Welcome to your dashboard!"})
		})
		appGroup.GET("/settings", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "These are your settings."})
		})
	}
}
