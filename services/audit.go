// services/audit.go
package services

import (
	"encoding/json"
	"fmt"
	"go-jwt-api/db"
	"go-jwt-api/models"
	"log"
	"reflect"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type AuditData struct {
	Action     string
	ResourceId *string
	OldValues  interface{}
	NewValues  interface{}
}

func CreateAuditLog(c *gin.Context, auditData *AuditData, status int, success bool, errorMsg string, startTime time.Time) {
	var userId *uint
	var contextId *uint

	if uid, exists := c.Get("sub"); exists {
		if id, ok := uid.(uint); ok {
			userId = &id
		}
	}

	if cid, exists := c.Get("ctx"); exists {
		if id, ok := cid.(uint); ok && id != 0 {
			contextId = &id
		}
	}

	duration := time.Since(startTime).Milliseconds()

	var oldValues, newValues, changes json.RawMessage
	var err error

	if auditData != nil {
		if auditData.OldValues != nil {
			oldValues, err = json.Marshal(auditData.OldValues)
			if err != nil {
				log.Printf("Error marshaling old values: %v", err)
				oldValues = json.RawMessage(`{}`)
			}
		}

		if auditData.NewValues != nil {
			newValues, err = json.Marshal(auditData.NewValues)
			if err != nil {
				log.Printf("Error marshaling new values: %v", err)
				newValues = json.RawMessage(`{}`)
			}
		}

		if auditData.OldValues != nil && auditData.NewValues != nil {
			changesMap := calculateChanges(auditData.OldValues, auditData.NewValues)
			if len(changesMap) > 0 {
				changes, err = json.Marshal(changesMap)
				if err != nil {
					log.Printf("Error marshaling changes: %v", err)
					changes = json.RawMessage(`{}`)
				}
			}
		}
	}

	action := "unknown"
	if auditData != nil && auditData.Action != "" {
		action = auditData.Action
	} else {
		action = determineAction(c.Request.Method, c.FullPath())
	}

	auditLog := models.AuditLog{
		UserId:     userId,
		ContextId:  contextId,
		Action:     action,
		Route:      c.FullPath(),
		Method:     c.Request.Method,
		ResourceId: auditData.ResourceId,
		OldValues:  oldValues,
		NewValues:  newValues,
		Changes:    changes,
		IPAddress:  c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
		Status:     status,
		Success:    success,
		ErrorMsg:   errorMsg,
		Duration:   duration,
	}

	go func() {
		if err := db.DB.Create(&auditLog).Error; err != nil {
			log.Printf("Failed to create audit log: %v", err)
		}
	}()
}

func determineAction(method, route string) string {
	route = strings.ToLower(route)
	method = strings.ToUpper(method)

	switch method {
	case "POST":
		if strings.Contains(route, "signin") {
			return "user_login"
		} else if strings.Contains(route, "signup") {
			return "user_register"
		} else if strings.Contains(route, "signout") {
			return "user_logout"
		} else if strings.Contains(route, "context") {
			return "context_create"
		} else if strings.Contains(route, "verify-email") {
			return "email_verification"
		} else if strings.Contains(route, "forgot-password") {
			return "password_reset_request"
		} else if strings.Contains(route, "reset-password") {
			return "password_reset"
		} else if strings.Contains(route, "select") {
			return "context_select"
		}
		return "create"

	case "PUT", "PATCH":
		if strings.Contains(route, "activate") {
			return "context_activate"
		} else if strings.Contains(route, "deactivate") {
			return "context_deactivate"
		} else if strings.Contains(route, "/me") {
			return "user_update"
		} else if strings.Contains(route, "context") {
			return "context_update"
		}
		return "update"

	case "DELETE":
		if strings.Contains(route, "context") {
			return "context_delete"
		} else if strings.Contains(route, "signout") {
			return "user_logout"
		}
		return "delete"

	case "GET":
		if strings.Contains(route, "/me") {
			return "user_profile_view"
		} else if strings.Contains(route, "context") {
			return "context_view"
		} else if strings.Contains(route, "csrf-token") {
			return "csrf_token_request"
		}
		return "read"

	default:
		return fmt.Sprintf("%s_%s", strings.ToLower(method), strings.ReplaceAll(strings.Trim(route, "/"), "/", "_"))
	}
}

func calculateChanges(oldValue, newValue interface{}) map[string]interface{} {
	changes := make(map[string]interface{})

	oldMap := structToMap(oldValue)
	newMap := structToMap(newValue)

	for key, newVal := range newMap {
		if oldVal, exists := oldMap[key]; exists {
			if !reflect.DeepEqual(oldVal, newVal) {
				changes[key] = map[string]interface{}{
					"old": oldVal,
					"new": newVal,
				}
			}
		} else {
			changes[key] = map[string]interface{}{
				"old": nil,
				"new": newVal,
			}
		}
	}

	for key, oldVal := range oldMap {
		if _, exists := newMap[key]; !exists {
			changes[key] = map[string]interface{}{
				"old": oldVal,
				"new": nil,
			}
		}
	}

	return changes
}

func structToMap(obj interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	if obj == nil {
		return result
	}

	if m, ok := obj.(map[string]interface{}); ok {
		return m
	}

	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		return result
	}

	err = json.Unmarshal(jsonBytes, &result)
	if err != nil {
		return result
	}

	sensitiveFields := []string{"password", "token", "secret"}
	for _, field := range sensitiveFields {
		for key := range result {
			if strings.Contains(strings.ToLower(key), field) {
				result[key] = "[REDACTED]"
			}
		}
	}

	return result
}

func GetAuditLogs(contextId *uint) ([]models.AuditLog, error) {
	var logs []models.AuditLog

	err := db.DB.Model(&models.AuditLog{}).
		Where("context_id = ?", *contextId).
		Order("id ASC").
		Find(&logs).Error

	return logs, err
}
