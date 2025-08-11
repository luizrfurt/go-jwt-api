// middlewares/audit.go
package middlewares

import (
	"bytes"
	"encoding/json"
	"go-jwt-api/services"
	"io"
	"time"

	"github.com/gin-gonic/gin"
)

type AuditMiddlewareConfig struct {
	SkipRoutes  []string
	SkipMethods []string
}

type responseBodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (r responseBodyWriter) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}

func AuditMiddleware(config ...AuditMiddlewareConfig) gin.HandlerFunc {
	cfg := AuditMiddlewareConfig{}
	if len(config) > 0 {
		cfg = config[0]
	}

	return func(c *gin.Context) {
		startTime := time.Now()

		if shouldSkipRoute(c.FullPath(), c.Request.Method, cfg) {
			c.Next()
			return
		}

		var requestBody []byte
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			if c.Request.Body != nil {
				requestBody, _ = io.ReadAll(c.Request.Body)
				c.Request.Body = io.NopCloser(bytes.NewBuffer(requestBody))
			}
		}

		w := &responseBodyWriter{body: &bytes.Buffer{}, ResponseWriter: c.Writer}
		c.Writer = w

		c.Next()

		go func() {
			var auditData *services.AuditData
			if data, exists := c.Get("audit_data"); exists {
				if ad, ok := data.(*services.AuditData); ok {
					auditData = ad
				}
			}

			if auditData == nil {
				auditData = &services.AuditData{}
			}

			if len(requestBody) > 0 && auditData.NewValues == nil {
				if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
					var reqData map[string]interface{}
					if err := json.Unmarshal(requestBody, &reqData); err == nil {
						auditData.NewValues = reqData
					}
				}
			}

			success := c.Writer.Status() < 400
			var errorMsg string
			if !success {
				var response map[string]interface{}
				if err := json.Unmarshal(w.body.Bytes(), &response); err == nil {
					if content, ok := response["content"].(map[string]interface{}); ok {
						if errMsg, ok := content["error"].(string); ok {
							errorMsg = errMsg
						}
					}
				}
			}

			services.CreateAuditLog(c, auditData, c.Writer.Status(), success, errorMsg, startTime)
		}()
	}
}

func shouldSkipRoute(route, method string, config AuditMiddlewareConfig) bool {
	defaultSkipRoutes := []string{
		"/",
		"/auth/csrf-token",
	}

	defaultSkipMethods := []string{}

	skipRoutes := append(defaultSkipRoutes, config.SkipRoutes...)
	for _, skipRoute := range skipRoutes {
		if route == skipRoute {
			return true
		}
	}

	skipMethods := append(defaultSkipMethods, config.SkipMethods...)
	for _, skipMethod := range skipMethods {
		if method == skipMethod {
			return true
		}
	}

	return false
}

func SetAuditData(c *gin.Context, action string, resourceId *string, oldValues, newValues interface{}) {
	auditData := &services.AuditData{
		Action:     action,
		ResourceId: resourceId,
		OldValues:  oldValues,
		NewValues:  newValues,
	}
	c.Set("audit_data", auditData)
}
