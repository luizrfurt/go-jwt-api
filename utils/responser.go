// utils/responser.go
package utils

import (
	"time"

	"github.com/gin-gonic/gin"
)

type Meta struct {
	Timestamp string `json:"timestamp"`
}

type Response struct {
	Content interface{} `json:"content,omitempty"`
	Meta    Meta        `json:"meta"`
}

func SendJSON(c *gin.Context, status int, content interface{}) {
	c.JSON(status, Response{
		Content: content,
		Meta:    Meta{Timestamp: time.Now().Format(time.RFC3339)},
	})
}

func SendJSONError(c *gin.Context, status int, err interface{}) {
	c.JSON(status, Response{
		Content: err,
		Meta:    Meta{Timestamp: time.Now().Format(time.RFC3339)},
	})
}
