// routes/task.go
package routes

import (
	"go-jwt-api/handlers"
	"go-jwt-api/middlewares"

	"github.com/gin-gonic/gin"
)

func RegisterTaskRoutes(r *gin.Engine) {
	taskGroup := r.Group("/tasks")
	taskGroup.Use(middlewares.AuthMiddleware(), middlewares.ContextAccessMiddleware(), middlewares.CSRFMiddleware())
	{
		taskGroup.GET("", handlers.GetMyTasks)
		taskGroup.POST("", handlers.CreateTask)
		taskGroup.PUT("/:id", handlers.UpdateTask)
		taskGroup.DELETE("/:id", handlers.DeleteTask)
	}
}
