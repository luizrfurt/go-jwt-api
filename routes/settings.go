// routes/settings.go
package routes

import (
	"go-jwt-api/middlewares"

	"github.com/gin-gonic/gin"
)

func RegisterSettingsRoutes(r *gin.Engine) {
	settingsGroup := r.Group("/settings")
	settingsGroup.Use(middlewares.AuthMiddleware())
	{
		settingsGroup.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "These are your settings."})
		})
		// settingsGroup.PUT("/profile", updateProfile)
		// settingsGroup.PUT("/password", changePassword)
		// settingsGroup.GET("/preferences", getPreferences)
	}
}
