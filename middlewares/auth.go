package middlewares

import (
	"go-jwt-api/services"
	"go-jwt-api/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr, err := c.Cookie("access_token")
		if err != nil || tokenStr == "" {
			utils.SendJSONError(c, http.StatusUnauthorized, gin.H{
				"error": "Missing or malformed token",
			}, []string{})
			c.Abort()
			return
		}

		claims, err := services.ValidateAccessToken(tokenStr)
		if err != nil {
			switch err.Error() {
			case "invalid token":
				utils.SendJSONError(c, http.StatusUnauthorized, gin.H{
					"error": "Invalid token",
				}, []string{})
			case "invalid token type":
				utils.SendJSONError(c, http.StatusUnauthorized, gin.H{
					"error": "Invalid token type. Access token required",
				}, []string{})
			default:
				utils.SendJSONError(c, http.StatusUnauthorized, gin.H{
					"error": "Token validation failed",
				}, []string{})
			}
			c.Abort()
			return
		}

		c.Set("id", claims.Id)
		c.Set("user", claims.Username)
		c.Set("email", claims.Email)
		c.Next()
	}
}
