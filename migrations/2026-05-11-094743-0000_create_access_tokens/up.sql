CREATE TABLE access_tokens
(
    id         BLOB(16) PRIMARY KEY NOT NULL CHECK (LENGTH(id) = 16),
    username   VARCHAR(64)          NOT NULL CHECK (LENGTH(username) > 0 AND LENGTH(username) <= 64),
    client_id  VARCHAR(64)          NOT NULL CHECK (LENGTH(client_id) > 0 AND LENGTH(client_id) <= 64),
    scopes     VARCHAR(16)          NOT NULL CHECK (LENGTH(scopes) <= 16), -- TODO - Consider refactoring into a foreign reference
    issued_at  TIMESTAMP            NOT NULL,
    expires_at TIMESTAMP            NOT NULL,
    not_before TIMESTAMP            NOT NULL
);
