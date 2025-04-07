package pg

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/ulixes-bloom/ya-gophkeeper/internal/domain"
	"github.com/ulixes-bloom/ya-gophkeeper/pkg/security"
)

type PostgresDBTestSuite struct {
	suite.Suite
	storage   *postgresDB
	container *postgres.PostgresContainer
	ctx       context.Context
}

func (s *PostgresDBTestSuite) SetupSuite() {
	s.ctx = context.Background()
	var err error

	// Setup container and storage
	s.container, err = postgres.Run(s.ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("gophermart"),
		postgres.WithUsername("user"),
		postgres.WithPassword("password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second)),
	)
	require.NoError(s.T(), err)

	connStr, err := s.container.ConnectionString(s.ctx, "sslmode=disable")
	require.NoError(s.T(), err)

	db, err := sql.Open("pgx", connStr)
	require.NoError(s.T(), err)

	s.storage, err = New(s.ctx, db, "./../migrations")
	require.NoError(s.T(), err)
}

func (s *PostgresDBTestSuite) TearDownSuite() {
	if s.container != nil {
		err := s.container.Terminate(s.ctx)
		require.NoError(s.T(), err)
	}
}

func (s *PostgresDBTestSuite) SetupTest() {
	// Clear database before each test
	_, err := s.storage.db.ExecContext(s.ctx, "TRUNCATE TABLE users, secrets RESTART IDENTITY CASCADE")
	require.NoError(s.T(), err)
}

func TestPostgresDBTestSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests in short mode")
	}
	suite.Run(t, new(PostgresDBTestSuite))
}

func (s *PostgresDBTestSuite) TestCreateUser() {
	tests := []struct {
		name        string
		login       string
		password    string
		wantError   error
		description string
	}{
		{
			name:        "successful creation",
			login:       "user1",
			password:    "password1",
			wantError:   nil,
			description: "should create user successfully",
		},
		{
			name:        "duplicate login",
			login:       "user1",
			password:    "password2",
			wantError:   domain.ErrLoginExists,
			description: "should fail when login already exists",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			passwordHash, err := security.HashPassword(tt.password)
			require.NoError(s.T(), err)

			_, err = s.storage.CreateUser(s.ctx, tt.login, passwordHash)
			if tt.wantError != nil {
				require.ErrorIs(s.T(), err, tt.wantError, tt.description)
				return
			}
			require.NoError(s.T(), err, tt.description)

			// Verify user was created
			dbUser, err := s.storage.FindUserByLogin(s.ctx, tt.login)
			require.NoError(s.T(), err)
			require.NotNil(s.T(), dbUser)
			require.Equal(s.T(), tt.login, dbUser.Login)
			require.Equal(s.T(), passwordHash, dbUser.PasswordHash)
		})
	}
}

func (s *PostgresDBTestSuite) TestFindUserByLogin() {
	// Setup test data
	login := "testuser"
	password := "testpassword"
	passwordHash, err := security.HashPassword(password)
	require.NoError(s.T(), err)

	_, err = s.storage.CreateUser(s.ctx, login, passwordHash)
	require.NoError(s.T(), err)

	tests := []struct {
		name        string
		login       string
		wantError   error
		description string
	}{
		{
			name:        "existing user",
			login:       login,
			wantError:   nil,
			description: "should find existing user",
		},
		{
			name:        "non-existent user",
			login:       "nonexistent",
			wantError:   domain.ErrUserNotFound,
			description: "should return error for non-existent user",
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			user, err := s.storage.FindUserByLogin(s.ctx, tt.login)
			if tt.wantError != nil {
				require.ErrorIs(s.T(), err, tt.wantError, tt.description)
				require.Nil(s.T(), user)
				return
			}
			require.NoError(s.T(), err, tt.description)
			require.NotNil(s.T(), user)
			require.Equal(s.T(), login, user.Login)
			require.Equal(s.T(), passwordHash, user.PasswordHash)
		})
	}
}

func (s *PostgresDBTestSuite) TestCreateAndGetSecret() {
	// Create test user
	userLogin := "secretuser"
	userPassword := "secretpassword"
	user, err := s.storage.CreateUser(s.ctx, userLogin, userPassword)
	fmt.Println(user)
	require.NoError(s.T(), err)

	secret := &domain.Secret{
		Name:     "test-secret",
		UserID:   user.ID,
		Type:     domain.CredentialsSecret,
		Data:     []byte("secret-data"),
		Metadata: `{"key": "value"}`,
		Version:  1,
	}

	s.Run("create and get secret", func() {
		// Test CreateSecret
		err := s.storage.CreateSecret(s.ctx, secret)
		require.NoError(s.T(), err)

		// Test GetLatestSecretByName
		dbSecret, err := s.storage.GetLatestSecretByName(s.ctx, secret.UserID, secret.Name)
		require.NoError(s.T(), err)
		require.NotNil(s.T(), dbSecret)

		// Verify all fields
		require.Equal(s.T(), secret.Name, dbSecret.Name)
		require.Equal(s.T(), secret.UserID, dbSecret.UserID)
		require.Equal(s.T(), secret.Type, dbSecret.Type)
		require.Equal(s.T(), secret.Data, dbSecret.Data)
		require.Equal(s.T(), secret.Metadata, dbSecret.Metadata)
		require.Equal(s.T(), secret.Version, dbSecret.Version)
		require.False(s.T(), dbSecret.CreatedAt.IsZero())

		// Test secret exists check
		exists, err := s.storage.IsSecretExist(s.ctx, secret.UserID, secret.Name)
		require.NoError(s.T(), err)
		require.True(s.T(), exists)
	})

	s.Run("get non-existent secret", func() {
		_, err := s.storage.GetLatestSecretByName(s.ctx, user.ID, "nonexistent")
		require.ErrorIs(s.T(), err, domain.ErrSecretNotFound)
	})

	s.Run("create duplicate secret", func() {
		// Should allow creating secrets with same name but different versions
		newVersion := &domain.Secret{
			Name:     secret.Name,
			UserID:   secret.UserID,
			Type:     secret.Type,
			Data:     []byte("new-data"),
			Metadata: `{"key":"new-value"}`,
			Version:  2,
		}

		err := s.storage.CreateSecret(s.ctx, newVersion)
		require.NoError(s.T(), err)

		// Verify we can get both versions
		v1, err := s.storage.GetSecretByVersion(s.ctx, secret.UserID, secret.Name, 1)
		require.NoError(s.T(), err)
		require.Equal(s.T(), 1, int(v1.Version))

		v2, err := s.storage.GetSecretByVersion(s.ctx, secret.UserID, secret.Name, 2)
		require.NoError(s.T(), err)
		require.Equal(s.T(), 2, int(v2.Version))

		// Latest should be version 2
		latest, err := s.storage.GetLatestSecretByName(s.ctx, secret.UserID, secret.Name)
		require.NoError(s.T(), err)
		require.Equal(s.T(), 2, int(latest.Version))
	})

	s.Run("delete secret", func() {
		err := s.storage.DeleteSecret(s.ctx, secret.UserID, secret.Name)
		require.NoError(s.T(), err)

		// Verify secret is gone
		exists, err := s.storage.IsSecretExist(s.ctx, secret.UserID, secret.Name)
		require.NoError(s.T(), err)
		require.False(s.T(), exists)

		_, err = s.storage.GetLatestSecretByName(s.ctx, secret.UserID, secret.Name)
		require.ErrorIs(s.T(), err, domain.ErrSecretNotFound)
	})
}

func (s *PostgresDBTestSuite) TestGetSecretsList() {
	// Create test user
	user, err := s.storage.CreateUser(s.ctx, "listuser", "password")
	require.NoError(s.T(), err)

	// Create multiple secrets
	secrets := []*domain.Secret{
		{
			Name:     "secret1",
			UserID:   user.ID,
			Type:     domain.CredentialsSecret,
			Data:     []byte("data1"),
			Metadata: "{}",
			Version:  1,
		},
		{
			Name:     "secret2",
			UserID:   user.ID,
			Type:     domain.CredentialsSecret,
			Data:     []byte("data2"),
			Metadata: "{}",
			Version:  1,
		},
		{
			Name:     "secret1", // New version of secret1
			UserID:   user.ID,
			Type:     domain.CredentialsSecret,
			Data:     []byte("data1-v2"),
			Metadata: "{}",
			Version:  2,
		},
	}

	for _, secret := range secrets {
		err := s.storage.CreateSecret(s.ctx, secret)
		require.NoError(s.T(), err)
	}

	// Test GetSecretsList
	list, err := s.storage.GetSecretsList(s.ctx, user.ID)
	require.NoError(s.T(), err)
	require.Len(s.T(), list, 2) // Should return distinct names
	require.Contains(s.T(), list, "secret1")
	require.Contains(s.T(), list, "secret2")

	// Test for user with no secrets
	list, err = s.storage.GetSecretsList(s.ctx, "nonexistent-user")
	require.Error(s.T(), err)
	require.Empty(s.T(), list)
}
