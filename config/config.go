// config/config.go
package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/spf13/cast"
)

type Config struct {
	Port         string
	PortWeb      string
	Environment  string
	DBHost       string
	DBPort       string
	DBUser       string
	DBPassword   string
	DBName       string
	JwtKey       string
	MailHost     string
	MailPort     int
	MailUsername string
	MailPassword string
}

var AppConfig *Config

func LoadConfig() {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found or failed to load it")
	}

	AppConfig = &Config{
		Port:         getEnv("PORT", "8080"),
		PortWeb:      getEnv("PORT_WEB", "8080"),
		Environment:  getEnv("ENVIRONMENT", "development"),
		DBHost:       getEnv("DB_HOST", "localhost"),
		DBPort:       getEnv("DB_PORT", "5432"),
		DBUser:       getEnv("DB_USER", "postgres"),
		DBPassword:   getEnv("DB_PASSWORD", "postgres"),
		DBName:       getEnv("DB_NAME", "core"),
		JwtKey:       getEnv("JWT_SECRET", "super-secret-key"),
		MailHost:     os.Getenv("MAIL_HOST"),
		MailPort:     cast.ToInt(os.Getenv("MAIL_PORT")),
		MailUsername: os.Getenv("MAIL_USERNAME"),
		MailPassword: os.Getenv("MAIL_PASSWORD"),
	}
}

func getEnv(key, defaultValue string) string {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	}
	return val
}
