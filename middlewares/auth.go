// middlewares/auth.go
package middlewares

import (
	"go-jwt-api/services"
	"net/http"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenStr string
		var err error
		tokenStr, err = c.Cookie("access_token")
		if err != nil || tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing or malformed token"})
			return
		}

		claims, err := services.ValidateAccessToken(tokenStr)
		if err != nil {
			switch err.Error() {
			case "invalid token":
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			case "invalid token type":
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token type. Access token required"})
			default:
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token validation failed"})
			}
			return
		}

		c.Set("user", claims.Username)
		c.Next()
	}
}
