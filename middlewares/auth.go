// middleware/auth.go
package middleware

import (
	"go-jwt-api/auth"
	"net/http"

	//"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenStr string
		//authHeader := c.GetHeader("Authorization")
		//if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		//	tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
		//} else {
		var err error
		tokenStr, err = c.Cookie("access_token")
		if err != nil || tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing or malformed token"})
			return
		}
		//}
		claims := &auth.Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return auth.JwtKey, nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}
		if claims.TokenType != "access" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token type. Access token required"})
			return
		}
		c.Set("user", claims.Username)
		c.Next()
	}
}
