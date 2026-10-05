-- MySQL schema for JdbcDaoImpl / JdbcUserDetailsManager.
--
-- NOTE: whether username comparisons are case-insensitive depends on the column
-- collation, not the type. MySQL's default collations are accent- and
-- case-insensitive (for example utf8mb4_0900_ai_ci on MySQL 8), which matches the
-- HSQLDB 'varchar_ignorecase' behaviour. If your server or schema uses a binary or
-- '_bin'/'_cs' collation, lookups become case-sensitive.
--
-- 'boolean' is an alias for tinyint(1) on MySQL and works with ResultSet.getBoolean.

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
