CREATE TABLE access_tokens_temp
(
    id         BLOB(16) PRIMARY KEY NOT NULL CHECK (LENGTH(id) = 16),
    username   VARCHAR(64)          NOT NULL CHECK (LENGTH(username) > 0 AND LENGTH(username) <= 64),
    client_id  VARCHAR(64)          NOT NULL REFERENCES client_configurations (client_id) ON DELETE CASCADE,
    scopes     BINARY               NOT NULL CHECK (json_valid(scopes) AND json_type(scopes) = 'array'),
    issued_at  TIMESTAMP            NOT NULL,
    expires_at TIMESTAMP            NOT NULL,
    not_before TIMESTAMP            NOT NULL
);

INSERT INTO access_tokens_temp
SELECT
    id,
    username,
    client_id,
    (
        WITH RECURSIVE split(word, rest) AS (
            SELECT
                CASE WHEN instr(trim(at.scopes), ' ') > 0
                         THEN substr(trim(at.scopes), 1, instr(trim(at.scopes), ' ') - 1)
                     ELSE trim(at.scopes) END,
                CASE WHEN instr(trim(at.scopes), ' ') > 0
                         THEN substr(trim(at.scopes), instr(trim(at.scopes), ' ') + 1)
                     ELSE '' END
            UNION ALL
            SELECT
                CASE WHEN instr(trim(rest), ' ') > 0
                         THEN substr(trim(rest), 1, instr(trim(rest), ' ') - 1)
                     ELSE trim(rest) END,
                CASE WHEN instr(trim(rest), ' ') > 0
                         THEN substr(trim(rest), instr(trim(rest), ' ') + 1)
                     ELSE '' END
            FROM split WHERE rest != ''
        )
        SELECT json_group_array(word) FROM split
    ) as scopes,
    issued_at,
    expires_at,
    not_before
FROM access_tokens at;

DROP TABLE access_tokens;

ALTER TABLE access_tokens_temp RENAME TO access_tokens;