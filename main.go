// main.go
package main

import (
	"go-jwt-api/db"
	"go-jwt-api/routes"

	"github.com/gin-gonic/gin"
)

func main() {
	db.InitDB()
	r := gin.Default()
	routes.SetupRoutes(r)
	r.Run(":8080")
}
