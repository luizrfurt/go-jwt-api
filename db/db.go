// db/db.go
package db

import (
	"fmt"
	"log"

	"go-jwt-api/config"
	"go-jwt-api/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDBConfig() {
	c := config.AppConfig

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		c.DBHost, c.DBUser, c.DBPassword, c.DBName, c.DBPort,
	)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	err = DB.AutoMigrate(
		&models.User{},
		&models.Context{},
		&models.UserContext{},
		&models.AuditLog{},
		&models.Task{},
	)
	if err != nil {
		log.Fatal("Failed to auto-migrate database:", err)
	}

	err = DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_context_unique ON user_contexts(user_id, context_id)").Error
	if err != nil {
		log.Fatal("Failed to create unique index:", err)
	}
}
