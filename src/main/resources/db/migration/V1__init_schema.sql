CREATE TABLE users (
    user_id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone_number VARCHAR(255),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    username VARCHAR(255),
    date_of_birth DATE,
    password VARCHAR(255) NOT NULL,
    is_authorized BOOLEAN NOT NULL DEFAULT TRUE,
    role VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE TABLE client_apps (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    api_token VARCHAR(255) NOT NULL UNIQUE,
    redirect_url VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    client_id UUID,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    expired_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE TABLE user_clients (
    user_id UUID NOT NULL REFERENCES users(user_id),
    client_id UUID NOT NULL REFERENCES client_apps(id),
    PRIMARY KEY (user_id, client_id)
);
