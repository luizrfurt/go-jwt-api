package main

import (
	"go-jwt-api/db"
	"go-jwt-api/routes"

	"github.com/gin-gonic/gin"
)

func main() {
	db.InitDB()
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "API is running"})
	})

	routes.SetupRoutes(r)
	r.Run(":8080")
}
