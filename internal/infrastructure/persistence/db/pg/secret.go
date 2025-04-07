package pg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ulixes-bloom/ya-gophkeeper/internal/domain"
)

// CreateSecret stores a new secret in the database.
func (p *postgresDB) CreateSecret(ctx context.Context, secret *domain.Secret) error {
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO secrets (name, user_id, secret_type, content, metadata, version)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id;`, secret.Name, secret.UserID, secret.Type, secret.Data, secret.Metadata, secret.Version)
	if err != nil {
		return fmt.Errorf("pg.CreateSecret: %w", err)
	}

	return nil
}

// GetSecretsList retrieves a list of distinct secret names for a given user.
func (p *postgresDB) GetSecretsList(ctx context.Context, userID string) ([]string, error) {
	var list []string

	rows, err := p.db.QueryContext(ctx, `
		SELECT DISTINCT name
		FROM secrets
		WHERE user_id=$1;`, userID)
	if err != nil {
		return []string{}, fmt.Errorf("pg.GetSecretsList: %w", err)
	}

	for rows.Next() {
		var secretName string
		err := rows.Scan(&secretName)
		if err != nil {
			return []string{}, fmt.Errorf("pg.GetSecretsList: %w", err)
		}
		list = append(list, secretName)
	}

	return list, err
}

func (p *postgresDB) IsSecretExist(ctx context.Context, userID, secretName string) (bool, error) {
	var exists int
	err := p.db.QueryRowContext(ctx, `
		SELECT 1
		FROM secrets
		WHERE user_id=$1 AND name=$2;`, userID, secretName).Scan(&exists)

	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}

		return false, fmt.Errorf("pg.GetLatestSecretByName: %w", err)
	}

	return true, nil
}

// GetLatestSecretByName retrieves the latest version of a secret for a given user and secret name.
func (p *postgresDB) GetLatestSecretByName(ctx context.Context, userID, secretName string) (*domain.Secret, error) {
	secret := domain.Secret{
		Name:   secretName,
		UserID: userID,
	}
	err := p.db.QueryRowContext(ctx, `
		SELECT id, secret_type, content, metadata::text, version, created_at
		FROM secrets
		WHERE user_id=$1 AND name=$2
		ORDER BY version DESC
		LIMIT 1;`, userID, secretName).Scan(&secret.ID, &secret.Type, &secret.Data, &secret.Metadata, &secret.Version, &secret.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("pg.GetLatestSecretByName: %w", domain.ErrSecretNotFound)
		}

		return nil, fmt.Errorf("pg.GetLatestSecretByName: %w", err)
	}

	return &secret, nil
}

// GetSecretByVersion retrieves a specific version of a secret for a given user and secret name.
func (p *postgresDB) GetSecretByVersion(ctx context.Context, userID, secretName string, version int32) (*domain.Secret, error) {
	secret := domain.Secret{
		Name:    secretName,
		UserID:  userID,
		Version: version,
	}
	err := p.db.QueryRowContext(ctx, `
		SELECT id, secret_type, content, metadata, created_at
		FROM secrets
		WHERE user_id=$1 AND name=$2 AND version=$3;`, userID, secretName, version).Scan(&secret.ID, &secret.Type, &secret.Data, &secret.Metadata, &secret.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("pg.GetSecretByVersion: %w", domain.ErrSecretVersionNotFound)
		}
		return nil, fmt.Errorf("pg.GetSecretByVersion: %w", err)
	}

	return &secret, nil
}

// DeleteSecret removes a all secret versions from the database for a given user and secret name.
func (p *postgresDB) DeleteSecret(ctx context.Context, userID, secretName string) error {
	_, err := p.db.ExecContext(ctx, `
		DELETE FROM secrets
		WHERE user_id=$1 AND name=$2`, userID, secretName)
	if err != nil {
		return fmt.Errorf("pg.DeleteSecret: %w", err)
	}

	return nil
}
