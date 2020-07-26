/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.config.annotation.authentication;

import javax.sql.DataSource;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;

/**
 * @author Rob Winch
 */
public class NamespaceJdbcUserServiceTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void jdbcUserService() throws Exception {
		this.spring.register(DataSourceConfig.class, JdbcUserServiceConfig.class).autowire();

		this.mockMvc.perform(formLogin()).andExpect(authenticated().withUsername("user"));
	}

	@Test
	public void jdbcUserServiceCustom() throws Exception {
		this.spring.register(CustomDataSourceConfig.class, CustomJdbcUserServiceSampleConfig.class).autowire();

		this.mockMvc.perform(formLogin()).andExpect(authenticated().withUsername("user").withRoles("DBA", "USER"));
	}

	@EnableWebSecurity
	static class JdbcUserServiceConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		private DataSource dataSource;

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.jdbcAuthentication()
					.withDefaultSchema()
					.withUser(PasswordEncodedUser.user())
					.dataSource(this.dataSource); // jdbc-user-service@data-source-ref
			// @formatter:on
		}

	}

	@Configuration
	static class DataSourceConfig {

		@Bean
		public DataSource dataSource() {
			EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder();
			return builder.setType(EmbeddedDatabaseType.HSQL).build();
		}

	}

	@EnableWebSecurity
	static class CustomJdbcUserServiceSampleConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		private DataSource dataSource;

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.jdbcAuthentication()
				// jdbc-user-service@dataSource
				.dataSource(this.dataSource)
				// jdbc-user-service@cache-ref
				.userCache(new CustomUserCache())
				// jdbc-user-service@users-byusername-query
				.usersByUsernameQuery("select principal,credentials,true from users where principal = ?")
				// jdbc-user-service@authorities-by-username-query
				.authoritiesByUsernameQuery("select principal,role from roles where principal = ?")
				// jdbc-user-service@group-authorities-by-username-query
				.groupAuthoritiesByUsername(JdbcDaoImpl.DEF_GROUP_AUTHORITIES_BY_USERNAME_QUERY)
				// jdbc-user-service@role-prefix
				.rolePrefix("ROLE_");
			// @formatter:on

		}

		static class CustomUserCache implements UserCache {

			@Override
			public UserDetails getUserFromCache(String username) {
				return null;
			}

			@Override
			public void putUserInCache(UserDetails user) {
			}

			@Override
			public void removeUserFromCache(String username) {
			}

		}

	}

	@Configuration
	static class CustomDataSourceConfig {

		@Bean
		public DataSource dataSource() {
			EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder()
					// simulate that the DB already has the schema loaded and users in it
					.addScript("CustomJdbcUserServiceSampleConfig.sql");
			return builder.setType(EmbeddedDatabaseType.HSQL).build();
		}

	}

}
