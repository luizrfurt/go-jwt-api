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
			utils.SendJSON(c, http.StatusUnauthorized, gin.H{
				"error": "Access token is required",
			}, []string{})
			c.Abort()
			return
		}

		claims, status, message, _ := services.ValidateAccessToken(tokenStr)
		if status != 0 {
			utils.SendJSON(c, status, gin.H{
				"error": message,
			}, []string{})
			c.Abort()
			return
		}

		c.Set("sub", claims.Sub)
		c.Set("ctx", claims.Ctx)
		c.Next()
	}
}

func ContextAccessMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId, exists := c.Get("sub")
		if !exists {
			utils.SendJSON(c, http.StatusUnauthorized, gin.H{
				"error": "User not found in context",
			}, []string{})
			c.Abort()
			return
		}

		contextId, exists := c.Get("ctx")
		if !exists || contextId.(uint) == 0 {
			utils.SendJSON(c, http.StatusBadRequest, gin.H{
				"error": "No active context",
			}, []string{})
			c.Abort()
			return
		}

		if !services.HasContextAccess(userId.(uint), contextId.(uint)) {
			utils.SendJSON(c, http.StatusForbidden, gin.H{
				"error": "Access denied to this context",
			}, []string{})
			c.Abort()
			return
		}

		c.Next()
	}
}
