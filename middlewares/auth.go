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
				"error": "Access token is required",
			}, []string{})
			c.Abort()
			return
		}

		claims, err := services.ValidateAccessToken(tokenStr)
		if err != nil {
			switch err.Error() {
			case "invalid token":
				utils.SendJSONError(c, http.StatusUnauthorized, gin.H{
					"error": "The provided token is invalid or expired",
				}, []string{})
			case "invalid token type":
				utils.SendJSONError(c, http.StatusUnauthorized, gin.H{
					"error": "Invalid token type provided. Access token is required",
				}, []string{})
			default:
				utils.SendJSONError(c, http.StatusUnauthorized, gin.H{
					"error": "Authentication failed. Please provide a valid access token",
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
