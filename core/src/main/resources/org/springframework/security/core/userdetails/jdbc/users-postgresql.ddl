-- PostgreSQL schema for JdbcDaoImpl / JdbcUserDetailsManager.
--
-- NOTE: PostgreSQL has no equivalent of the HSQLDB 'varchar_ignorecase' type, so
-- username comparisons here are CASE-SENSITIVE ('josh' will not match 'Josh').
-- To restore case-insensitive lookups, enable the citext extension and use
-- 'citext' in place of 'varchar(50)' below:
--     create extension if not exists citext;
-- Creating an extension requires elevated privileges, so it is not done here.

create table users
(
    username varchar(50)  not null primary key,
    password varchar(500) not null,
    enabled  boolean      not null
);

create table authorities
(
    username  varchar(50) not null,
    authority varchar(50) not null,
    constraint fk_authorities_users foreign key (username) references users (username)
);

create unique index ix_auth_username on authorities (username, authority);
