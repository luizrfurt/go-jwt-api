// models/user.go
package models

import "time"

type User struct {
	Id                  uint   `gorm:"primaryKey"`
	Name                string `gorm:"not null"`
	Username            string `gorm:"uniqueIndex;not null"`
	Email               string `gorm:"uniqueIndex;not null"`
	Password            string `gorm:"not null"`
	ForgotPasswordToken string `gorm:"default:null"`
	CreatedAt           time.Time
	UpdatedAt           time.Time
}
