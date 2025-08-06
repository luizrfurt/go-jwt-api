// models/context.go
package models

import "time"

type Context struct {
	Id          uint   `gorm:"primaryKey"`
	Name        string `gorm:"not null"`
	Description string `gorm:"type:text"`
	OwnerId     uint   `gorm:"not null"`
	Owner       User   `gorm:"foreignKey:OwnerId"`
	Active      bool   `gorm:"default:true"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type UserContext struct {
	Id        uint    `gorm:"primaryKey"`
	UserId    uint    `gorm:"not null"`
	ContextId uint    `gorm:"not null"`
	Role      string  `gorm:"default:'member'"`
	Selected  bool    `gorm:"default:false"`
	User      User    `gorm:"foreignKey:UserId"`
	Context   Context `gorm:"foreignKey:ContextId"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func init() {
}
