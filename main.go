// main.go
package main

import (
	"go-jwt-api/config"
	"go-jwt-api/db"
	"go-jwt-api/routes"
	"go-jwt-api/services"
	"go-jwt-api/utils"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadConfig()
	db.InitDBConfig()
	services.InitAuthConfig()

	r := gin.Default()

	portWeb := config.AppConfig.PortWeb

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:" + portWeb},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Authorization"},
		AllowCredentials: true,
	}))

	r.GET("/", func(c *gin.Context) {
		utils.SendJSON(c, http.StatusOK, gin.H{"message": "API is running"}, []string{})
	})

	r.GET("/docs", func(c *gin.Context) {
		c.File("./tools/docs.html")
	})

	routes.SetupRoutes(r)

	r.Run(":" + config.AppConfig.Port)
}
