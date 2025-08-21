// routes/router.go
package routes

import (
	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine) {
	RegisterAuthRoutes(r)
	RegisterContextRoutes(r)
	RegisterAuditRoutes(r)
	RegisterTaskRoutes(r)
}
