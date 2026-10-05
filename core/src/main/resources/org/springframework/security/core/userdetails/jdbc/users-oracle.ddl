-- Oracle schema for JdbcDaoImpl / JdbcUserDetailsManager.
--
-- NOTE: 'enabled' is number(1) rather than boolean. Oracle only added a BOOLEAN
-- column type in 23ai; number(1) also works on 19c and 21c. The Oracle JDBC driver
-- maps number(1) to/from Java booleans, so ResultSet.getBoolean and
-- PreparedStatement.setBoolean both work as expected.
--
-- NOTE: username comparisons here are CASE-SENSITIVE ('josh' will not match
-- 'Josh'), unlike the HSQLDB and H2 scripts. For case-insensitive lookups, add a
-- collation to the username columns (Oracle 12.2+), which requires the session
-- parameters NLS_COMP=LINGUISTIC and NLS_SORT=BINARY_CI:
--     username varchar2(50) collate binary_ci not null

create table users
(
    username varchar2(50)  not null primary key,
    password varchar2(500) not null,
    enabled  number(1)     not null
);

create table authorities
(
    username  varchar2(50) not null,
    authority varchar2(50) not null,
    constraint fk_authorities_users foreign key (username) references users (username)
);

create unique index ix_auth_username on authorities (username, authority);
