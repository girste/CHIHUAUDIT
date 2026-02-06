package models

import (
	"time"
)

type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

func GetUserByUsername(username string) (*User, error) {
	u := &User{}
	var createdAt string
	err := DB.QueryRow(
		"SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &createdAt)
	if err != nil {
		return nil, err
	}
	u.CreatedAt, _ = time.Parse(time.DateTime, createdAt)
	return u, nil
}

func CreateUser(username, passwordHash string) (*User, error) {
	result, err := DB.Exec(
		"INSERT INTO users (username, password_hash) VALUES (?, ?)",
		username, passwordHash,
	)
	if err != nil {
		return nil, err
	}
	id, _ := result.LastInsertId()
	u := &User{
		ID:        int(id),
		Username:  username,
		CreatedAt: time.Now().UTC(),
	}
	return u, nil
}
