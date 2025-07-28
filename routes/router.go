// routes/router.go
package routes

import (
	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine) {
	RegisterAuthRoutes(r)
	RegisterHomeRoutes(r)
	RegisterSettingsRoutes(r)
}
