// main.go
package main

import (
	"net/http"

	"go-jwt-api/config"
	"go-jwt-api/db"
	"go-jwt-api/middlewares"
	"go-jwt-api/routes"
	"go-jwt-api/services"
	"go-jwt-api/utils"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadConfig()
	db.InitDBConfig()
	services.InitAuthConfig()

	r := gin.Default()

	portWeb := config.AppConfig.PortWeb

	r.Use(middlewares.SecurityHeaders())

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:" + portWeb},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-CSRF-Token"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	r.GET("/", func(c *gin.Context) {
		utils.SendJSON(c, http.StatusOK, gin.H{"message": "API is running"}, []string{})
	})

	routes.SetupRoutes(r)

	r.Run(":" + config.AppConfig.Port)
}
