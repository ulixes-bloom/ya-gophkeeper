package pg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ulixes-bloom/ya-gophkeeper/internal/domain"
)

// CreateUser registers a new user in the database.
func (p *postgresDB) CreateUser(ctx context.Context, login, passwordHash string) (*domain.User, error) {
	var userID string

	err := p.db.QueryRowContext(ctx, `
		INSERT INTO users (login, password_hash)
		VALUES ($1, $2)
		RETURNING id;`, login, passwordHash).Scan(&userID)
	if err != nil {
		if isUniqueViolation(err, "users_login_key") {
			return nil, fmt.Errorf("pg.CreateUser: %w", domain.ErrLoginExists)
		}
		return nil, fmt.Errorf("pg.CreateUser: %w", err)
	}

	return &domain.User{ID: userID, Login: login, PasswordHash: passwordHash}, err
}

// FindUserByLogin searches for a user by login.
func (p *postgresDB) FindUserByLogin(ctx context.Context, login string) (*domain.User, error) {
	var user domain.User
	err := p.db.QueryRowContext(ctx, `
		SELECT id, login, password_hash
		FROM users
		WHERE login=$1;`, login).Scan(&user.ID, &user.Login, &user.PasswordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("pg.FindUserByLogin: %w", domain.ErrUserNotFound)
		}
		return nil, fmt.Errorf("pg.FindUserByLogin: %w", err)
	}

	return &user, err
}
