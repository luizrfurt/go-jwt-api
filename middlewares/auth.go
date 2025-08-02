// src/middlewares/auth.go
package middlewares

import (
	"go-jwt-api/services"
	"go-jwt-api/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr, err := c.Cookie("session.xaccess")
		if err != nil || tokenStr == "" {
			utils.SendJSONError(c, http.StatusUnauthorized, gin.H{
				"error": "Access token is required",
			}, []string{})
			c.Abort()
			return
		}

		claims, status, message, _ := services.ValidateAccessToken(tokenStr)
		if status != 0 {
			utils.SendJSONError(c, status, gin.H{
				"error": message,
			}, []string{})
			c.Abort()
			return
		}

		c.Set("sub", claims.Id)
		c.Next()
	}
}
