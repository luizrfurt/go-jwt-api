// routes/context.go
package routes

import (
	"go-jwt-api/handlers"
	"go-jwt-api/middlewares"

	"github.com/gin-gonic/gin"
)

func RegisterContextRoutes(r *gin.Engine) {
	contextGroup := r.Group("/contexts")
	contextGroup.Use(middlewares.AuthMiddleware(), middlewares.CSRFMiddleware())
	{
		contextGroup.GET("/", handlers.GetMyContexts)
		contextGroup.GET("/active", handlers.GetActiveContext)
		contextGroup.POST("", handlers.CreateContext)
		contextGroup.POST("/select", handlers.SelectContext)
	}
}
