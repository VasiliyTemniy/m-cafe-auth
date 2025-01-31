-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS auth (
	user_id UUID NOT NULL PRIMARY KEY,
	password_hash varchar(100) NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS auth;
-- +goose StatementEnd