// utils/mailer.go
package utils

import (
	"go-jwt-api/config"
	"log"

	"gopkg.in/gomail.v2"
)

func SendEmail(to string, subject string, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", "no-reply@example.com")
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer(
		config.AppConfig.MailHost,
		config.AppConfig.MailPort,
		config.AppConfig.MailUsername,
		config.AppConfig.MailPassword,
	)

	if err := d.DialAndSend(m); err != nil {
		log.Println("Email sending failed:", err)
		return err
	}

	log.Println("Email sent to:", to)
	return nil
}
