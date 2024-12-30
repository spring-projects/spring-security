/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.context.ApplicationContextException;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * <tt>UserDetailsService</tt> implementation which retrieves the user details (username,
 * password, enabled flag, and authorities) from a database using JDBC queries.
 *
 * <h3>Default Schema</h3> A default database schema is assumed, with two tables "users"
 * and "authorities".
 *
 * <h4>The Users table</h4>
 *
 * This table contains the login name, password and enabled status of the user.
 *
 * <table summary="The Users Table">
 * <tr>
 * <th>Column</th>
 * </tr>
 * <tr>
 * <td>username</td>
 * </tr>
 * <tr>
 * <td>password</td>
 * </tr>
 * <tr>
 * <td>enabled</td>
 * </tr>
 * </table>
 *
 * <h4>The Authorities Table</h4>
 *
 * <table summary="The Authorities Table">
 * <tr>
 * <th>Column</th>
 * </tr>
 * <tr>
 * <td>username</td>
 * </tr>
 * <tr>
 * <td>authority</td>
 * </tr>
 * </table>
 *
 * If you are using an existing schema you will have to set the queries
 * <tt>usersByUsernameQuery</tt> and <tt>authoritiesByUsernameQuery</tt> to match your
 * database setup (see {@link #DEF_USERS_BY_USERNAME_QUERY} and
 * {@link #DEF_AUTHORITIES_BY_USERNAME_QUERY}).
 *
 * <p>
 * In order to minimise backward compatibility issues, this implementation doesn't
 * recognise the expiration of user accounts or the expiration of user credentials.
 * However, it does recognise and honour the user enabled/disabled column. This should map
 * to a <tt>boolean</tt> type in the result set (the SQL type will depend on the database
 * you are using). All the other columns map to <tt>String</tt>s.
 *
 * <h3>Group Support</h3> Support for group-based authorities can be enabled by setting
 * the <tt>enableGroups</tt> property to <tt>true</tt> (you may also then wish to set
 * <tt>enableAuthorities</tt> to <tt>false</tt> to disable loading of authorities
 * directly). With this approach, authorities are allocated to groups and a user's
 * authorities are determined based on the groups they are a member of. The net result is
 * the same (a UserDetails containing a set of <tt>GrantedAuthority</tt>s is loaded), but
 * the different persistence strategy may be more suitable for the administration of some
 * applications.
 * <p>
 * When groups are being used, the tables "groups", "group_members" and
 * "group_authorities" are used. See {@link #DEF_GROUP_AUTHORITIES_BY_USERNAME_QUERY} for
 * the default query which is used to load the group authorities. Again you can customize
 * this by setting the <tt>groupAuthoritiesByUsernameQuery</tt> property, but the format
 * of the rows returned should match the default.
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @author Luke Taylor
 */
public class JdbcDaoImpl extends JdbcDaoSupport implements UserDetailsService, MessageSourceAware {

	public static final String DEFAULT_USER_SCHEMA_DDL_LOCATION = "org/springframework/security/core/userdetails/jdbc/users.ddl";

	// @formatter:off
	public static final String DEF_USERS_BY_USERNAME_QUERY = "select username,password,enabled "
			+ "from users "
			+ "where username = ?";
	// @formatter:on

	// @formatter:off
	public static final String DEF_AUTHORITIES_BY_USERNAME_QUERY = "select username,authority "
			+ "from authorities "
			+ "where username = ?";
	// @formatter:on

	// @formatter:off
	public static final String DEF_GROUP_AUTHORITIES_BY_USERNAME_QUERY = "select g.id, g.group_name, ga.authority "
			+ "from groups g, group_members gm, group_authorities ga "
			+ "where gm.username = ? " + "and g.id = ga.group_id " + "and g.id = gm.group_id";
	// @formatter:on

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private String authoritiesByUsernameQuery;

	private String groupAuthoritiesByUsernameQuery;

	private String usersByUsernameQuery;

	private String rolePrefix = "";

	private boolean usernameBasedPrimaryKey = true;

	private boolean enableAuthorities = true;

	private boolean enableGroups;

	public JdbcDaoImpl() {
		this.usersByUsernameQuery = DEF_USERS_BY_USERNAME_QUERY;
		this.authoritiesByUsernameQuery = DEF_AUTHORITIES_BY_USERNAME_QUERY;
		this.groupAuthoritiesByUsernameQuery = DEF_GROUP_AUTHORITIES_BY_USERNAME_QUERY;
	}

	/**
	 * @return the messages
	 */
	protected MessageSourceAccessor getMessages() {
		return this.messages;
	}

	/**
	 * Allows subclasses to add their own granted authorities to the list to be returned
	 * in the <tt>UserDetails</tt>.
	 * @param username the username, for use by finder methods
	 * @param authorities the current granted authorities, as populated from the
	 * <code>authoritiesByUsername</code> mapping
	 */
	protected void addCustomAuthorities(String username, List<GrantedAuthority> authorities) {
	}

	public String getUsersByUsernameQuery() {
		return this.usersByUsernameQuery;
	}

	@Override
	protected void initDao() throws ApplicationContextException {
		Assert.isTrue(this.enableAuthorities || this.enableGroups,
				"Use of either authorities or groups must be enabled");
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		List<UserDetails> users = loadUsersByUsername(username);
		if (users.isEmpty()) {
			this.logger.debug("Query returned no results for user '" + username + "'");
			throw new UsernameNotFoundException(this.messages.getMessage("JdbcDaoImpl.notFound",
					new Object[] { username }, "Username {0} not found"));
		}
		UserDetails user = users.get(0); // contains no GrantedAuthority[]
		Set<GrantedAuthority> dbAuthsSet = new HashSet<>();
		if (this.enableAuthorities) {
			dbAuthsSet.addAll(loadUserAuthorities(user.getUsername()));
		}
		if (this.enableGroups) {
			dbAuthsSet.addAll(loadGroupAuthorities(user.getUsername()));
		}
		List<GrantedAuthority> dbAuths = new ArrayList<>(dbAuthsSet);
		addCustomAuthorities(user.getUsername(), dbAuths);
		if (dbAuths.isEmpty()) {
			this.logger.debug("User '" + username + "' has no authorities and will be treated as 'not found'");
			throw new UsernameNotFoundException(this.messages.getMessage("JdbcDaoImpl.noAuthority",
					new Object[] { username }, "User {0} has no GrantedAuthority"));
		}
		return createUserDetails(username, user, dbAuths);
	}

	/**
	 * Executes the SQL <tt>usersByUsernameQuery</tt> and returns a list of UserDetails
	 * objects. There should normally only be one matching user.
	 */
	protected List<UserDetails> loadUsersByUsername(String username) {
		// @formatter:off
		RowMapper<UserDetails> mapper = (rs, rowNum) -> {
			String username1 = rs.getString(1);
			String password = rs.getString(2);
			boolean enabled = rs.getBoolean(3);
			return new User(username1, password, enabled, true, true, true, AuthorityUtils.NO_AUTHORITIES);
		};
		// @formatter:on
		return getJdbcTemplate().query(this.usersByUsernameQuery, mapper, username);
	}

	/**
	 * Loads authorities by executing the SQL from <tt>authoritiesByUsernameQuery</tt>.
	 * @return a list of GrantedAuthority objects for the user
	 */
	protected List<GrantedAuthority> loadUserAuthorities(String username) {
		return getJdbcTemplate().query(this.authoritiesByUsernameQuery, new String[] { username }, (rs, rowNum) -> {
			String roleName = JdbcDaoImpl.this.rolePrefix + rs.getString(2);
			return new SimpleGrantedAuthority(roleName);
		});
	}

	/**
	 * Loads authorities by executing the SQL from
	 * <tt>groupAuthoritiesByUsernameQuery</tt>.
	 * @return a list of GrantedAuthority objects for the user
	 */
	protected List<GrantedAuthority> loadGroupAuthorities(String username) {
		return getJdbcTemplate().query(this.groupAuthoritiesByUsernameQuery, new String[] { username },
				(rs, rowNum) -> {
					String roleName = getRolePrefix() + rs.getString(3);
					return new SimpleGrantedAuthority(roleName);
				});
	}

	/**
	 * Can be overridden to customize the creation of the final UserDetailsObject which is
	 * returned by the <tt>loadUserByUsername</tt> method.
	 * @param username the name originally passed to loadUserByUsername
	 * @param userFromUserQuery the object returned from the execution of the
	 * @param combinedAuthorities the combined array of authorities from all the authority
	 * loading queries.
	 * @return the final UserDetails which should be used in the system.
	 */
	protected UserDetails createUserDetails(String username, UserDetails userFromUserQuery,
			List<GrantedAuthority> combinedAuthorities) {
		String returnUsername = userFromUserQuery.getUsername();
		if (!this.usernameBasedPrimaryKey) {
			returnUsername = username;
		}
		return new User(returnUsername, userFromUserQuery.getPassword(), userFromUserQuery.isEnabled(),
				userFromUserQuery.isAccountNonExpired(), userFromUserQuery.isCredentialsNonExpired(),
				userFromUserQuery.isAccountNonLocked(), combinedAuthorities);
	}

	/**
	 * Allows the default query string used to retrieve authorities based on username to
	 * be overridden, if default table or column names need to be changed. The default
	 * query is {@link #DEF_AUTHORITIES_BY_USERNAME_QUERY}; when modifying this query,
	 * ensure that all returned columns are mapped back to the same column positions as in
	 * the default query.
	 * @param queryString The SQL query string to set
	 */
	public void setAuthoritiesByUsernameQuery(String queryString) {
		this.authoritiesByUsernameQuery = queryString;
	}

	protected String getAuthoritiesByUsernameQuery() {
		return this.authoritiesByUsernameQuery;
	}

	/**
	 * Allows the default query string used to retrieve group authorities based on
	 * username to be overridden, if default table or column names need to be changed. The
	 * default query is {@link #DEF_GROUP_AUTHORITIES_BY_USERNAME_QUERY}; when modifying
	 * this query, ensure that all returned columns are mapped back to the same column
	 * positions as in the default query.
	 * @param queryString The SQL query string to set
	 */
	public void setGroupAuthoritiesByUsernameQuery(String queryString) {
		this.groupAuthoritiesByUsernameQuery = queryString;
	}

	/**
	 * Allows a default role prefix to be specified. If this is set to a non-empty value,
	 * then it is automatically prepended to any roles read in from the db. This may for
	 * example be used to add the <tt>ROLE_</tt> prefix expected to exist in role names
	 * (by default) by some other Spring Security classes, in the case that the prefix is
	 * not already present in the db.
	 * @param rolePrefix the new prefix
	 */
	public void setRolePrefix(String rolePrefix) {
		this.rolePrefix = rolePrefix;
	}

	protected String getRolePrefix() {
		return this.rolePrefix;
	}

	/**
	 * If <code>true</code> (the default), indicates the
	 * {@link #getUsersByUsernameQuery()} returns a username in response to a query. If
	 * <code>false</code>, indicates that a primary key is used instead. If set to
	 * <code>true</code>, the class will use the database-derived username in the returned
	 * <code>UserDetails</code>. If <code>false</code>, the class will use the
	 * {@link #loadUserByUsername(String)} derived username in the returned
	 * <code>UserDetails</code>.
	 * @param usernameBasedPrimaryKey <code>true</code> if the mapping queries return the
	 * username <code>String</code>, or <code>false</code> if the mapping returns a
	 * database primary key.
	 */
	public void setUsernameBasedPrimaryKey(boolean usernameBasedPrimaryKey) {
		this.usernameBasedPrimaryKey = usernameBasedPrimaryKey;
	}

	protected boolean isUsernameBasedPrimaryKey() {
		return this.usernameBasedPrimaryKey;
	}

	/**
	 * Allows the default query string used to retrieve users based on username to be
	 * overridden, if default table or column names need to be changed. The default query
	 * is {@link #DEF_USERS_BY_USERNAME_QUERY}; when modifying this query, ensure that all
	 * returned columns are mapped back to the same column positions as in the default
	 * query. If the 'enabled' column does not exist in the source database, a permanent
	 * true value for this column may be returned by using a query similar to
	 *
	 * <pre>
	 * &quot;select username,password,'true' as enabled from users where username = ?&quot;
	 * </pre>
	 * @param usersByUsernameQueryString The query string to set
	 */
	public void setUsersByUsernameQuery(String usersByUsernameQueryString) {
		this.usersByUsernameQuery = usersByUsernameQueryString;
	}

	protected boolean getEnableAuthorities() {
		return this.enableAuthorities;
	}

	/**
	 * Enables loading of authorities (roles) from the authorities table. Defaults to true
	 */
	public void setEnableAuthorities(boolean enableAuthorities) {
		this.enableAuthorities = enableAuthorities;
	}

	protected boolean getEnableGroups() {
		return this.enableGroups;
	}

	/**
	 * Enables support for group authorities. Defaults to false
	 * @param enableGroups
	 */
	public void setEnableGroups(boolean enableGroups) {
		this.enableGroups = enableGroups;
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		Assert.notNull(messageSource, "messageSource cannot be null");
		this.messages = new MessageSourceAccessor(messageSource);
	}

}
