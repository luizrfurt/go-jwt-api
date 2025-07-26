// routes/auth.go
package routes

import (
	"go-jwt-api/auth"
	"go-jwt-api/middlewares"

	"github.com/gin-gonic/gin"
)

func RegisterAuthRoutes(r *gin.Engine) {
	authGroup := r.Group("/auth")
	{
		authGroup.POST("/signup", auth.SignUp)
		authGroup.POST("/signin", auth.SignIn)
		authGroup.POST("/refresh", auth.RefreshToken)
		authGroup.DELETE("/signout", auth.SignOut)

		protected := authGroup.Group("/")
		protected.Use(middlewares.AuthMiddleware())
		{
			protected.GET("/me", auth.Me)
		}
	}
}
