-- Microsoft SQL Server schema for JdbcDaoImpl / JdbcUserDetailsManager.
--
-- NOTE: SQL Server has no BOOLEAN type, so 'enabled' is 'bit'. The driver maps
-- this to/from Java booleans, so ResultSet.getBoolean and
-- PreparedStatement.setBoolean both work as expected.
--
-- NOTE: whether username comparisons are case-insensitive depends on the column
-- collation, not the type. SQL Server's default collations are case-insensitive
-- (for example SQL_Latin1_General_CP1_CI_AS), which matches the HSQLDB
-- 'varchar_ignorecase' behaviour. A '_CS_' collation makes lookups case-sensitive.

create table users
(
    username varchar(50)  not null primary key,
    password varchar(500) not null,
    enabled  bit          not null
);

create table authorities
(
    username  varchar(50) not null,
    authority varchar(50) not null,
    constraint fk_authorities_users foreign key (username) references users (username)
);

create unique index ix_auth_username on authorities (username, authority);
