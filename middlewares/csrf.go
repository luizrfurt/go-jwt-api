// src/middlewares/csrf.go
package middlewares

import (
	"net/http"

	"go-jwt-api/config"
	"go-jwt-api/utils"

	"github.com/gin-gonic/gin"
)

func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if config.AppConfig.Environment != "production" {
			c.Next()
			return
		}

		method := c.Request.Method
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			c.Next()
			return
		}

		csrfCookie, err := c.Cookie("session.xcsrf")
		if err != nil {
			utils.SendJSONError(c, http.StatusUnauthorized, gin.H{
				"error": "CSRF token missing",
			}, []string{})
			c.Abort()
			return
		}

		csrfHeader := c.GetHeader("X-CSRF-Token")
		if csrfHeader == "" || csrfHeader != csrfCookie {
			utils.SendJSONError(c, http.StatusUnauthorized, gin.H{
				"error": "Invalid CSRF token",
			}, []string{})
			c.Abort()
			return
		}

		c.Next()
	}
}
