-- db/migrations/20250316203304_create_secrets_table.up.sql

CREATE TYPE secret_type AS ENUM ('credentials', 'text', 'file', 'payment_card');


CREATE TABLE secrets
(
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_type secret_type NOT NULL,
    content BYTEA,
    metadata JSONB DEFAULT '{}'::JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    version INT DEFAULT 1
);

-- Добавляем индекс для ускорения поиска по user_id
CREATE INDEX idx_secrets_user_id ON secrets(user_id);