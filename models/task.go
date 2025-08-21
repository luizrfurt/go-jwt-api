// models/task.go
package models

import "time"

type Task struct {
	Id        uint      `gorm:"primaryKey" json:"id"`
	Title     string    `gorm:"not null" json:"title"`
	Content   string    `gorm:"type:text" json:"content"`
	Status    string    `gorm:"default:'to_do'" json:"status"`
	UserId    uint      `gorm:"not null;index" json:"user_id"`
	ContextId uint      `gorm:"not null;index" json:"context_id"`
	User      User      `gorm:"foreignKey:UserId" json:"-"`
	Context   Context   `gorm:"foreignKey:ContextId" json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
