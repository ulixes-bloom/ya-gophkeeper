-- db/migrations/20250316202920_create_users_table.up.sql

CREATE TABLE users
(
    id SERIAL PRIMARY KEY,
    login VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);
