// models/audit_log.go
package models

import (
	"encoding/json"
	"time"
)

type AuditLog struct {
	Id         uint            `gorm:"primaryKey" json:"id"`
	UserId     *uint           `gorm:"index" json:"user_id"`
	ContextId  *uint           `gorm:"index" json:"context_id"`
	Action     string          `gorm:"not null;index" json:"action"`
	Route      string          `gorm:"not null" json:"route"`
	Method     string          `gorm:"not null" json:"method"`
	ResourceId *string         `gorm:"index" json:"resource_id"`
	OldValues  json.RawMessage `gorm:"type:jsonb" json:"old_values,omitempty"`
	NewValues  json.RawMessage `gorm:"type:jsonb" json:"new_values,omitempty"`
	Changes    json.RawMessage `gorm:"type:jsonb" json:"changes,omitempty"`
	IPAddress  string          `gorm:"size:45" json:"ip_address"`
	UserAgent  string          `gorm:"type:text" json:"user_agent"`
	Status     int             `gorm:"not null" json:"status"`
	Success    bool            `gorm:"not null;index" json:"success"`
	ErrorMsg   string          `gorm:"type:text" json:"error_message,omitempty"`
	Duration   int64           `gorm:"not null" json:"duration_ms"`
	CreatedAt  time.Time       `gorm:"index" json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}
