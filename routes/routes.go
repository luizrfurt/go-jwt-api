// routes/routes.go
package routes

import (
	"go-jwt-api/auth"
	middleware "go-jwt-api/middlewares"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine) {
	authGroup := r.Group("/auth")
	{
		authGroup.POST("/signup", auth.SignUp)
		authGroup.POST("/signin", auth.SignIn)
		authGroup.POST("/refresh", auth.RefreshToken)
		authGroup.DELETE("/signout", auth.SignOut)
		protected := authGroup.Group("/")
		protected.Use(middleware.AuthMiddleware())
		{
			protected.GET("/me", auth.Me)
		}
	}
	appGroup := r.Group("/")
	appGroup.Use(middleware.AuthMiddleware())
	{
		appGroup.GET("/dashboard", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "Welcome to your dashboard!"})
		})
		appGroup.GET("/settings", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "These are your settings."})
		})
	}
}
