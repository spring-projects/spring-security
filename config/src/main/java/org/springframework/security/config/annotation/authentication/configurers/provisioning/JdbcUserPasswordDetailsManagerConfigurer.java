/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.annotation.authentication.configurers.provisioning;

import java.util.ArrayList;
import java.util.List;

import javax.sql.DataSource;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.jdbc.datasource.init.DataSourceInitializer;
import org.springframework.jdbc.datasource.init.DatabasePopulator;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.provisioning.JdbcUserPasswordDetailsManager;

/**
 * Configures an
 * {@link org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder}
 * to have JDBC authentication, with user management that will automatically update the encoding of a password
 * if necessary. It also allows easily adding users to the database used
 * for authentication and setting up the schema.
 *
 * <p>
 * The only required method is the {@link #dataSource(javax.sql.DataSource)} all other
 * methods have reasonable defaults.
 *
 * @param <B> the type of the {@link ProviderManagerBuilder} that is being configured
 * @author Rob Winch
 * @author Geir Hedemark
 * @since 6.3
 */
public final class JdbcUserPasswordDetailsManagerConfigurer<B extends ProviderManagerBuilder<B>>
		extends UserDetailsManagerConfigurer<B, JdbcUserPasswordDetailsManagerConfigurer<B>> {

	private DataSource dataSource;

	private List<Resource> initScripts = new ArrayList<>();

	public JdbcUserPasswordDetailsManagerConfigurer(JdbcUserPasswordDetailsManager manager) {
		super(manager);
	}

	public JdbcUserPasswordDetailsManagerConfigurer() {
		this(new JdbcUserPasswordDetailsManager());
	}

	/**
	 * Populates the {@link DataSource} to be used. This is the only required attribute.
	 * @param dataSource the {@link DataSource} to be used. Cannot be null.
	 * @return The {@link JdbcUserPasswordDetailsManagerConfigurer} used for additional
	 * customizations
	 */
	public JdbcUserPasswordDetailsManagerConfigurer<B> dataSource(DataSource dataSource) {
		this.dataSource = dataSource;
		getUserDetailsService().setDataSource(dataSource);
		return this;
	}

	/**
	 * Sets the query to be used for finding a user by their username. For example:
	 *
	 * <code>
	 *     select username,password,enabled from users where username = ?
	 * </code>
	 * @param query The query to use for selecting the username, password, and if the user
	 * is enabled by username. Must contain a single parameter for the username.
	 * @return The {@link JdbcUserPasswordDetailsManagerConfigurer} used for additional
	 * customizations
	 */
	public JdbcUserPasswordDetailsManagerConfigurer<B> usersByUsernameQuery(String query) {
		getUserDetailsService().setUsersByUsernameQuery(query);
		return this;
	}

	/**
	 * Sets the query to be used for updating a password for a user. For example:
	 *
	 * <code>
	 *     update users set password = ? where username = ?
	 * </code>
	 * @param query The query to use for setting the password for a user. Must contain a parameter for the password, and one for the username.
	 * @return The {@link JdbcUserPasswordDetailsManagerConfigurer} used for additional
	 * customizations
	 */
	public JdbcUserPasswordDetailsManagerConfigurer<B> changePasswordQuery(String query) {
		getUserDetailsService().setChangePasswordQuery(query);
		return this;
	}

	/**
	 * Sets the query to be used for finding a user's authorities by their username. For
	 * example:
	 *
	 * <code>
	 *     select username,authority from authorities where username = ?
	 * </code>
	 * @param query The query to use for selecting the username, authority by username.
	 * Must contain a single parameter for the username.
	 * @return The {@link JdbcUserPasswordDetailsManagerConfigurer} used for additional
	 * customizations
	 */
	public JdbcUserPasswordDetailsManagerConfigurer<B> authoritiesByUsernameQuery(String query) {
		getUserDetailsService().setAuthoritiesByUsernameQuery(query);
		return this;
	}

	/**
	 * An SQL statement to query user's group authorities given a username. For example:
	 *
	 * <code>
	 *     select
	 *         g.id, g.group_name, ga.authority
	 *     from
	 *         groups g, group_members gm, group_authorities ga
	 *     where
	 *         gm.username = ? and g.id = ga.group_id and g.id = gm.group_id
	 * </code>
	 * @param query The query to use for selecting the authorities by group. Must contain
	 * a single parameter for the username.
	 * @return The {@link JdbcUserPasswordDetailsManagerConfigurer} used for additional
	 * customizations
	 */
	public JdbcUserPasswordDetailsManagerConfigurer<B> groupAuthoritiesByUsernameQuery(String query) {
		JdbcUserPasswordDetailsManager userDetailsService = getUserDetailsService();
		userDetailsService.setEnableGroups(true);
		userDetailsService.setGroupAuthoritiesByUsernameQuery(query);
		return this;
	}

	/**
	 * A non-empty string prefix that will be added to role strings loaded from persistent
	 * storage (default is "").
	 * @param rolePrefix
	 * @return The {@link JdbcUserPasswordDetailsManagerConfigurer} used for additional
	 * customizations
	 */
	public JdbcUserPasswordDetailsManagerConfigurer<B> rolePrefix(String rolePrefix) {
		getUserDetailsService().setRolePrefix(rolePrefix);
		return this;
	}

	/**
	 * Defines the {@link UserCache} to use
	 * @param userCache the {@link UserCache} to use
	 * @return the {@link JdbcUserPasswordDetailsManagerConfigurer} for further customizations
	 */
	public JdbcUserPasswordDetailsManagerConfigurer<B> userCache(UserCache userCache) {
		getUserDetailsService().setUserCache(userCache);
		return this;
	}

	@Override
	protected void initUserDetailsService() throws Exception {
		if (!this.initScripts.isEmpty()) {
			getDataSourceInit().afterPropertiesSet();
		}
		super.initUserDetailsService();
	}

	@Override
	public JdbcUserPasswordDetailsManager getUserDetailsService() {
		return (JdbcUserPasswordDetailsManager) super.getUserDetailsService();
	}

	/**
	 * Populates the default schema that allows users and authorities to be stored.
	 * @return The {@link JdbcUserPasswordDetailsManagerConfigurer} used for additional
	 * customizations
	 */
	public JdbcUserPasswordDetailsManagerConfigurer<B> withDefaultSchema() {
		this.initScripts.add(new ClassPathResource("org/springframework/security/core/userdetails/jdbc/users.ddl"));
		return this;
	}

	protected DatabasePopulator getDatabasePopulator() {
		ResourceDatabasePopulator dbp = new ResourceDatabasePopulator();
		dbp.setScripts(this.initScripts.toArray(new Resource[0]));
		return dbp;
	}

	private DataSourceInitializer getDataSourceInit() {
		DataSourceInitializer dsi = new DataSourceInitializer();
		dsi.setDatabasePopulator(getDatabasePopulator());
		dsi.setDataSource(this.dataSource);
		return dsi;
	}

}
