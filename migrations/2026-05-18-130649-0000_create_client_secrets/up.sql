CREATE TABLE client_secrets
(
    id        BLOB(16) PRIMARY KEY NOT NULL CHECK (LENGTH(id) = 16),
    client_id VARCHAR(64)          NOT NULL REFERENCES client_configurations (client_id) ON DELETE CASCADE,
    hash      VARCHAR(128)         NOT NULL CHECK (LENGTH(hash) >= 50 AND LENGTH(hash) <= 128)
);