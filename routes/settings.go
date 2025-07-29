// routes/settings.go
package routes

import (
	"go-jwt-api/middlewares"
	"go-jwt-api/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

func RegisterSettingsRoutes(r *gin.Engine) {
	settingsGroup := r.Group("/settings")
	settingsGroup.Use(middlewares.AuthMiddleware())
	{
		settingsGroup.GET("/", func(c *gin.Context) {
			utils.SendJSON(c, http.StatusOK, gin.H{"message": "These are your settings."}, []string{})

		})
	}
}
