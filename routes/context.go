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
		contextGroup.GET("", handlers.GetMyContexts)
		contextGroup.POST("", handlers.CreateContext)
		contextGroup.PUT("/:id", handlers.UpdateContext)
		contextGroup.PATCH("/activate/:id", handlers.ActivateContext)
		contextGroup.PATCH("/deactivate/:id", handlers.DeactivateContext)
		contextGroup.DELETE("/:id", handlers.DeleteContext)
		
		contextGroup.GET("/selected", handlers.GetSelectedContext)
		contextGroup.POST("/select/:id", handlers.SelectContext)
	}
}
