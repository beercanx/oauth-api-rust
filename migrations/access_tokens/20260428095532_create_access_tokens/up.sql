CREATE TABLE access_tokens
(
    id         BLOB(16) PRIMARY KEY NOT NULL CHECK(LENGTH(id) = 16),
    username   VARCHAR(255) NOT NULL,
    client_id  VARCHAR(255) NOT NULL,
    scopes     VARCHAR(16)  NOT NULL, -- TODO - Consider refactoring into a foreign reference
    issued_at  TIMESTAMP    NOT NULL,
    expires_at TIMESTAMP    NOT NULL,
    not_before TIMESTAMP    NOT NULL
);

CREATE INDEX access_tokens_username_idx ON access_tokens (username);
CREATE INDEX access_tokens_client_id_idx ON access_tokens (client_id);
CREATE INDEX access_tokens_expires_at_idx ON access_tokens (expires_at);
