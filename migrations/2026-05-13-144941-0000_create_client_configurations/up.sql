CREATE TABLE client_configurations
(
    client_id           VARCHAR(64) NOT NULL PRIMARY KEY CHECK (LENGTH(client_id) > 0 AND LENGTH(client_id) <= 64),
    client_type         VARCHAR(12) NOT NULL CHECK (client_type IN ('confidential', 'public')),
    redirect_uris       BINARY      NOT NULL CHECK (json_valid(redirect_uris) AND json_type(redirect_uris) = 'array'),
    allowed_scopes      BINARY      NOT NULL CHECK (json_valid(allowed_scopes) AND json_type(allowed_scopes) = 'array'),
    allowed_actions     BINARY      NOT NULL CHECK (json_valid(allowed_actions) AND json_type(allowed_actions) = 'array'),
    allowed_grant_types BINARY      NOT NULL CHECK (json_valid(allowed_grant_types) AND json_type(allowed_grant_types) = 'array')
);
