CREATE TABLE access_tokens_temp
(
    id         BLOB(16) PRIMARY KEY NOT NULL CHECK (LENGTH(id) = 16),
    username   VARCHAR(64)          NOT NULL CHECK (LENGTH(username) > 0 AND LENGTH(username) <= 64),
    client_id  VARCHAR(64)          NOT NULL REFERENCES client_configurations (client_id) ON DELETE CASCADE,
    scopes     VARCHAR(16)          NOT NULL CHECK (LENGTH(scopes) <= 16),
    issued_at  TIMESTAMP            NOT NULL,
    expires_at TIMESTAMP            NOT NULL,
    not_before TIMESTAMP            NOT NULL
);

INSERT INTO access_tokens_temp
SELECT id,
       username,
       client_id,
       (SELECT group_concat(value, ' ') FROM json_each(at.scopes)) as scopes,
       issued_at,
       expires_at,
       not_before
FROM access_tokens at;

DROP TABLE access_tokens;

ALTER TABLE access_tokens_temp RENAME TO access_tokens;