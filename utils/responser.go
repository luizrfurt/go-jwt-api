// utils/responser.go
package utils

import (
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"
)

type Meta struct {
	Timestamp string `json:"timestamp"`
}

type ContentResponse struct {
	Message          string                 `json:"message,omitempty"`
	Error            string                 `json:"error,omitempty"`
	ValidationErrors map[string]string      `json:"validation_errors,omitempty"`
	User             interface{}            `json:"user,omitempty"`
	Data             interface{}            `json:"data"`
	Extra            map[string]interface{} `json:"-"`
}

type Response struct {
	Content ContentResponse `json:"content"`
	Meta    Meta            `json:"meta"`
}

func SendJSON(c *gin.Context, status int, content interface{}, data interface{}) {
	contentStruct := buildContentResponse(content, data)
	c.JSON(status, Response{
		Content: contentStruct,
		Meta:    Meta{Timestamp: time.Now().Format(time.RFC3339)},
	})
}

func SendJSONError(c *gin.Context, status int, content interface{}, data interface{}) {
	contentStruct := buildContentResponse(content, data)
	c.JSON(status, Response{
		Content: contentStruct,
		Meta:    Meta{Timestamp: time.Now().Format(time.RFC3339)},
	})
}

func buildContentResponse(content interface{}, data interface{}) ContentResponse {
	result := ContentResponse{Data: data, Extra: make(map[string]interface{})}

	switch v := content.(type) {
	case gin.H:
		for key, value := range v {
			switch key {
			case "message":
				if msg, ok := value.(string); ok {
					result.Message = msg
				}
			case "error":
				if err, ok := value.(string); ok {
					result.Error = err
				}
			case "validation_errors":
				if validationErrs, ok := value.(map[string]string); ok {
					result.ValidationErrors = validationErrs
				}
			case "user":
				result.User = value
			default:
				result.Extra[key] = value
			}
		}
	default:
		contentMap := toMap(v)
		for key, value := range contentMap {
			switch key {
			case "message":
				if msg, ok := value.(string); ok {
					result.Message = msg
				}
			case "error":
				if err, ok := value.(string); ok {
					result.Error = err
				}
			case "validation_errors":
				if validationErrs, ok := value.(map[string]string); ok {
					result.ValidationErrors = validationErrs
				}
			case "user":
				result.User = value
			default:
				result.Extra[key] = value
			}
		}
	}

	return result
}

func toMap(content interface{}) map[string]interface{} {
	switch v := content.(type) {
	case gin.H:
		return v
	default:
		var result map[string]interface{}
		bytes, _ := json.Marshal(v)
		_ = json.Unmarshal(bytes, &result)
		return result
	}
}
