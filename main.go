// main.go
package main

import (
	"go-jwt-api/config"
	"go-jwt-api/db"
	"go-jwt-api/routes"
	"go-jwt-api/services"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadConfig()
	db.InitDBConfig()
	services.InitAuthConfig()

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Authorization"},
		AllowCredentials: true,
	}))

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "API is running"})
	})

	routes.SetupRoutes(r)

	r.Run(":8080")
}
