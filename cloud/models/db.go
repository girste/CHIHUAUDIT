package models

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func InitDB(dbPath string) error {
	var err error
	DB, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	// Enable foreign keys and WAL mode for better concurrency.
	for _, pragma := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
	} {
		if _, err := DB.Exec(pragma); err != nil {
			return fmt.Errorf("%s: %w", pragma, err)
		}
	}
	DB.SetMaxOpenConns(25)
	DB.SetMaxIdleConns(5)
	DB.SetConnMaxLifetime(5 * time.Minute)

	if err = DB.Ping(); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}
	log.Println("Connected to database")
	return nil
}

func RunMigrations(sqlData []byte) error {
	_, err := DB.Exec(string(sqlData))
	if err != nil {
		return fmt.Errorf("run migration: %w", err)
	}
	log.Println("Migrations applied")
	return nil
}
