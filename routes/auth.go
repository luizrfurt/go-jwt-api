// routes/auth.go
package routes

import (
	"go-jwt-api/handlers"
	"go-jwt-api/middlewares"

	"github.com/gin-gonic/gin"
)

func RegisterAuthRoutes(r *gin.Engine) {
	authGroup := r.Group("/auth")
	{
		authGroup.POST("/signup", handlers.SignUp)
		authGroup.POST("/signin", handlers.SignIn)
		authGroup.POST("/refresh", handlers.Refresh)
		authGroup.DELETE("/signout", handlers.SignOut)

		protected := authGroup.Group("/")
		protected.Use(middlewares.AuthMiddleware())
		{
			protected.GET("/me", handlers.Me)
		}
	}
}
