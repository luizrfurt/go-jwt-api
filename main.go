// main.go
package main

//go:generate swag init -g main.go -o ./docs
// @title go-jwt-api
// @version 1.0
// @description JWT Authentication API with Gin using cookie-based sessions.
// @contact.name Admin
// @contact.email admin@mail.com
// @host localhost:3308
// @BasePath /
// @securityDefinitions.apikey CookieAuth
// @in cookie
// @name session.xaccess
// @description Authentication via HttpOnly cookie. Log in at /auth/signin to obtain it.
import (
	"net/http"

	"go-jwt-api/config"
	"go-jwt-api/db"
	"go-jwt-api/middlewares"
	"go-jwt-api/routes"
	"go-jwt-api/services"
	"go-jwt-api/utils"

	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	docs "go-jwt-api/docs"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadConfig()
	db.InitDBConfig()
	services.InitAuthConfig()

	docs.SwaggerInfo.Host = "localhost:" + config.AppConfig.Port
	docs.SwaggerInfo.Schemes = []string{"http"}
	docs.SwaggerInfo.BasePath = "/"

	r := gin.Default()

	portWeb := config.AppConfig.PortWeb

	r.Use(middlewares.SecurityHeaders())

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:" + portWeb},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-CSRF-Token"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	r.GET("/", HealthCheck)

	r.GET("/docs", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/docs/index.html")
	})
	r.GET("/docs/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))

	routes.SetupRoutes(r)

	r.Run(":" + config.AppConfig.Port)
}

// HealthCheck godoc
// @Summary Health check
// @Description Check if API is running
// @Tags Health
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router / [get]
func HealthCheck(c *gin.Context) {
	utils.SendJSON(c, http.StatusOK, gin.H{"message": "API is running"}, []string{})
}
