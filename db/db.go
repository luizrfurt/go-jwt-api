// db/db.go
package db

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func InitDB() {
	var err error
	DB, err = sql.Open("sqlite", "./core.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	createTable := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    );
    `

	_, err = DB.Exec(createTable)
	if err != nil {
		log.Fatal("Failed to create table:", err)
	}
}
