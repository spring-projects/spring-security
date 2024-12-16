create table one_time_tokens(
    token_value varchar(36) not null primary key,
    username    varchar_ignorecase(50) not null,
    expires_at  timestamp   not null
);
