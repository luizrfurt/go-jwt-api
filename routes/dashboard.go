// routes/home.go
package routes

import (
	"go-jwt-api/middlewares"
	"go-jwt-api/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

func RegisterHomeRoutes(r *gin.Engine) {
	homeGroup := r.Group("/home")
	homeGroup.Use(middlewares.AuthMiddleware())
	{
		homeGroup.GET("/", func(c *gin.Context) {
			utils.SendJSON(c, http.StatusOK, gin.H{"message": "Welcome to your home!"}, []string{})
		})
		// homeGroup.GET("/stats", getHomeStats)
		// homeGroup.GET("/recent", getRecentActivity)
	}
}
