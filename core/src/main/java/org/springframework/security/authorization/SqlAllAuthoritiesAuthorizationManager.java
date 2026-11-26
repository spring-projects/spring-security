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

package org.springframework.security.authorization;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import javax.sql.DataSource;

import org.jspecify.annotations.Nullable;

import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} that can lookup authorities using a configured SQL
 * statement
 *
 * @author Andrey Litvitski
 * @since 7.0.0
 */
public final class SqlAllAuthoritiesAuthorizationManager<T> implements AuthorizationManager<T> {

	private final NamedParameterJdbcOperations jdbc;

	private final @Nullable List<String> additionalAuthorities;

	private final String sql;

	private final boolean whenTrueMode;

	private SqlAllAuthoritiesAuthorizationManager(NamedParameterJdbcOperations jdbc, String sql,
			@Nullable List<String> additionalAuthorities, boolean whenTrueMode) {
		this.jdbc = jdbc;
		this.sql = sql;
		this.additionalAuthorities = additionalAuthorities;
		this.whenTrueMode = whenTrueMode;
	}

	@Override
	public AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication, T object) {
		List<String> additionalAuthorities = findAdditionalAuthorities(authentication.get().getName());
		if (additionalAuthorities.isEmpty()) {
			return new AuthorizationDecision(true);
		}
		else {
			return AllAuthoritiesAuthorizationManager.hasAllAuthorities(additionalAuthorities)
				.authorize(authentication, object);
		}
	}

	private List<String> findAdditionalAuthorities(String authenticationName) {
		Map<String, Object> params = Map.of("username", authenticationName);
		if (this.whenTrueMode) {
			List<Map<String, Object>> rows = this.jdbc.queryForList(this.sql, params);
			if (rows.isEmpty()) {
				return List.of();
			}
			return (this.additionalAuthorities == null) ? List.of() : List.copyOf(this.additionalAuthorities);
		}
		else {
			return this.jdbc.query(this.sql, params, (rs, rowNum) -> rs.getString(1));
		}
	}

	public static final class Builder<T> {

		@Nullable private NamedParameterJdbcOperations jdbc;

		@Nullable private List<String> additionalAuthorities;

		private boolean whenTrueMode;

		@Nullable private String sql;

		public Builder<T> whenTrue(String sql) {
			this.whenTrueMode = true;
			this.sql = sql;
			return this;
		}

		public Builder<T> selectAuthorities(String sql) {
			this.whenTrueMode = false;
			this.sql = sql;
			return this;
		}

		public Builder<T> additionalAuthorities(String... authorities) {
			this.additionalAuthorities = Arrays.asList(authorities);
			return this;
		}

		public Builder<T> dataSource(DataSource dataSource) {
			this.jdbc = new NamedParameterJdbcTemplate(dataSource);
			return this;
		}

		public SqlAllAuthoritiesAuthorizationManager<T> build() {
			Assert.notNull(this.jdbc, "jdbc cannot be null");
			Assert.notNull(this.sql, "sql cannot be null");
			return new SqlAllAuthoritiesAuthorizationManager<>(this.jdbc, this.sql, this.additionalAuthorities,
					this.whenTrueMode);
		}

	}

}
