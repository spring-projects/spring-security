-- Platform-neutral schema for JdbcDaoImpl / JdbcUserDetailsManager.
--
-- Uses only ISO/IEC 9075 (SQL:2016) core syntax: VARCHAR, BOOLEAN, and a UNIQUE
-- table constraint rather than CREATE INDEX, which the SQL standard does not define.
--
-- Prefer a platform-specific script where one exists. This script has been verified
-- on PostgreSQL, MySQL, H2, HSQLDB and Oracle 23ai or later. It will NOT run on:
--   - SQL Server, which has no BOOLEAN type -- use users-sqlserver.sql
--   - Oracle before 23ai, which has no BOOLEAN column type -- use users-oracle.sql
--
-- NOTE: username comparisons are CASE-SENSITIVE unless the platform's default
-- collation says otherwise (MySQL and SQL Server default to case-insensitive
-- collations; PostgreSQL and Oracle do not). The HSQLDB and H2 scripts use
-- 'varchar_ignorecase' to force case-insensitive comparison; there is no standard
-- equivalent, so behaviour here is platform-dependent.

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
    constraint fk_authorities_users foreign key (username) references users (username),
    constraint ix_auth_username unique (username, authority)
);
