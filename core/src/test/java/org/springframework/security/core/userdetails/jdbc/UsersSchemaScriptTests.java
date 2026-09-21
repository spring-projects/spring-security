/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.core.userdetails.jdbc;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.jdbc.AbstractSqlSchemaScriptTests;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Verifies the platform-specific {@code users-*.sql} schema scripts by running each one
 * against a real instance of the database it targets and then exercising
 * {@link JdbcUserDetailsManager} and {@link JdbcDaoImpl} against the result.
 *
 * <p>
 * The container-backed tests are skipped when no Docker daemon is available; the HSQLDB
 * and H2 tests always run.
 *
 * @author Josh Long
 */
class UsersSchemaScriptTests extends AbstractSqlSchemaScriptTests {

	private static final String LOCATION = "org/springframework/security/core/userdetails/jdbc/";

	@Test
	void hsqldbSchemaSupportsUserDetailsManager() throws Exception {
		verifySchemaScript("hsqldb", LOCATION + "users-hsqldb.sql", this::exerciseUserDetailsManager);
	}

	@Test
	void h2SchemaSupportsUserDetailsManager() throws Exception {
		verifySchemaScript("h2", LOCATION + "users-h2.sql", this::exerciseUserDetailsManager);
	}

	@Test
	void postgresqlSchemaSupportsUserDetailsManager() throws Exception {
		verifySchemaScript("postgresql", LOCATION + "users-postgresql.sql", this::exerciseUserDetailsManager);
	}

	@Test
	void mysqlSchemaSupportsUserDetailsManager() throws Exception {
		verifySchemaScript("mysql", LOCATION + "users-mysql.sql", this::exerciseUserDetailsManager);
	}

	@Test
	void oracleSchemaSupportsUserDetailsManager() throws Exception {
		verifySchemaScript("oracle", LOCATION + "users-oracle.sql", this::exerciseUserDetailsManager);
	}

	@Test
	void sqlserverSchemaSupportsUserDetailsManager() throws Exception {
		verifySchemaScript("sqlserver", LOCATION + "users-sqlserver.sql", this::exerciseUserDetailsManager);
	}

	@Test
	void genericSchemaSupportsUserDetailsManagerOnHsqldb() throws Exception {
		verifySchemaScript("hsqldb", LOCATION + "users-all.sql", ColumnCase.SENSITIVE,
				this::exerciseUserDetailsManager);
	}

	@Test
	void genericSchemaSupportsUserDetailsManagerOnH2() throws Exception {
		verifySchemaScript("h2", LOCATION + "users-all.sql", ColumnCase.SENSITIVE, this::exerciseUserDetailsManager);
	}

	@Test
	void genericSchemaSupportsUserDetailsManagerOnPostgresql() throws Exception {
		verifySchemaScript("postgresql", LOCATION + "users-all.sql", ColumnCase.SENSITIVE,
				this::exerciseUserDetailsManager);
	}

	/**
	 * Drives the full {@link JdbcUserDetailsManager} lifecycle against the freshly
	 * initialized schema: create a user, read it back, look it up by a differently cased
	 * name, update it, and delete it.
	 */
	private void exerciseUserDetailsManager(SchemaContext context) {
		JdbcUserDetailsManager users = new JdbcUserDetailsManager(context.getDataSource());
		users.setUsersByUsernameQuery(context.getUsersByUsernameQuery());
		users.setAuthoritiesByUsernameQuery(context.getAuthoritiesByUsernameQuery());
		users.setUserExistsSql(context.getUserExistsSql());

		assertThat(users.userExists("marcus")).isFalse();

		users.createUser(User.withUsername("marcus").password("{noop}wombat").roles("USER", "ADMIN").build());

		assertThat(users.userExists("marcus")).isTrue();

		UserDetails created = users.loadUserByUsername("marcus");
		assertThat(created.getUsername()).isEqualTo("marcus");
		assertThat(created.getPassword()).isEqualTo("{noop}wombat");
		assertThat(created.isEnabled()).isTrue();
		assertThat(created.getAuthorities()).extracting(GrantedAuthority::getAuthority)
			.containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");

		// the query supplied by the context makes this behave the same way on every
		// platform, whether or not it has a case-insensitive character type
		UserDetails mixedCase = users.loadUserByUsername("MaRcUs");
		assertThat(mixedCase.getUsername()).isEqualTo("marcus");
		assertThat(mixedCase.getAuthorities()).extracting(GrantedAuthority::getAuthority)
			.containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");

		users.updateUser(User.withUsername("marcus").password("{noop}koala").disabled(true).roles("USER").build());

		UserDetails updated = users.loadUserByUsername("marcus");
		assertThat(updated.getPassword()).isEqualTo("{noop}koala");
		assertThat(updated.isEnabled()).isFalse();
		assertThat(updated.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsExactly("ROLE_USER");

		users.deleteUser("marcus");

		assertThat(users.userExists("marcus")).isFalse();
		assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(() -> users.loadUserByUsername("marcus"));
	}

}
