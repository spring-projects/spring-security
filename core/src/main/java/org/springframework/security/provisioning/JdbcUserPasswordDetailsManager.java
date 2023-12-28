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

package org.springframework.security.provisioning;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.List;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContextException;
import org.springframework.core.log.LogMessage;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.util.Assert;

/**
 * Jdbc user management manager, based on the same table structure as the base class,
 * <tt>JdbcDaoImpl</tt>.
 * <p>
 * This manager will automatically keep the password of the
 * user encoded with the current password encoding, making it easier to manage
 * password security over time.
 * <p>
 * Provides CRUD operations for both users and groups. Note that if the
 * {@link #setEnableAuthorities(boolean) enableAuthorities} property is set to false,
 * calls to createUser, updateUser and deleteUser will not store the authorities from the
 * <tt>UserDetails</tt> or delete authorities for the user. Since this class cannot
 * differentiate between authorities which were loaded for an individual or for a group of
 * which the individual is a member, it's important that you take this into account when
 * using this implementation for managing your users.
 *
 * This class is an evolution of the previous JdbcUserDetailsManager, which was part of spring security since version 2.0
 *
 * @author Luke Taylor
 * @author Geir Hedemark
 * @since 6.3
 */
public class JdbcUserPasswordDetailsManager extends JdbcDaoImpl implements UserDetailsManager, GroupManager, UserDetailsPasswordService {

	public static final String DEF_CREATE_USER_QUERY = "insert into users (username, password, enabled) values (?,?,?)";

	public static final String DEF_DELETE_USER_QUERY = "delete from users where username = ?";

	public static final String DEF_UPDATE_USER_QUERY = "update users set password = ?, enabled = ? where username = ?";

	public static final String DEF_INSERT_AUTHORITY_QUERY = "insert into authorities (username, authority) values (?,?)";

	public static final String DEF_DELETE_USER_AUTHORITIES_QUERY = "delete from authorities where username = ?";

	public static final String DEF_USER_EXISTS_QUERY = "select username from users where username = ?";

	public static final String DEF_CHANGE_PASSWORD_QUERY = "update users set password = ? where username = ?";

	public static final String DEF_FIND_GROUPS_QUERY = "select group_name from groups";

	public static final String DEF_FIND_USERS_IN_GROUP_QUERY = "select username from group_members gm, groups g "
			+ "where gm.group_id = g.id and g.group_name = ?";

	public static final String DEF_INSERT_GROUP_QUERY = "insert into groups (group_name) values (?)";

	public static final String DEF_FIND_GROUP_ID_QUERY = "select id from groups where group_name = ?";

	public static final String DEF_INSERT_GROUP_AUTHORITY_QUERY = "insert into group_authorities (group_id, authority) values (?,?)";

	public static final String DEF_DELETE_GROUP_QUERY = "delete from groups where id = ?";

	public static final String DEF_DELETE_GROUP_AUTHORITIES_QUERY = "delete from group_authorities where group_id = ?";

	public static final String DEF_DELETE_GROUP_MEMBERS_QUERY = "delete from group_members where group_id = ?";

	public static final String DEF_RENAME_GROUP_QUERY = "update groups set group_name = ? where group_name = ?";

	public static final String DEF_INSERT_GROUP_MEMBER_QUERY = "insert into group_members (group_id, username) values (?,?)";

	public static final String DEF_DELETE_GROUP_MEMBER_QUERY = "delete from group_members where group_id = ? and username = ?";

	public static final String DEF_GROUP_AUTHORITIES_QUERY_QUERY = "select g.id, g.group_name, ga.authority "
			+ "from groups g, group_authorities ga " + "where g.group_name = ? " + "and g.id = ga.group_id ";

	public static final String DEF_DELETE_GROUP_AUTHORITY_QUERY = "delete from group_authorities where group_id = ? and authority = ?";

	protected final Log logger = LogFactory.getLog(getClass());

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private String createUserQuery = DEF_CREATE_USER_QUERY;

	private String deleteUserQuery = DEF_DELETE_USER_QUERY;

	private String updateUserQuery = DEF_UPDATE_USER_QUERY;

	private String createAuthorityQuery = DEF_INSERT_AUTHORITY_QUERY;

	private String deleteUserAuthoritiesQuery = DEF_DELETE_USER_AUTHORITIES_QUERY;

	private String userExistsQuery = DEF_USER_EXISTS_QUERY;

	private String changePasswordQuery = DEF_CHANGE_PASSWORD_QUERY;

	private String findAllGroupsQuery = DEF_FIND_GROUPS_QUERY;

	private String findUsersInGroupQuery = DEF_FIND_USERS_IN_GROUP_QUERY;

	private String insertGroupQuery = DEF_INSERT_GROUP_QUERY;

	private String findGroupIdQuery = DEF_FIND_GROUP_ID_QUERY;

	private String insertGroupAuthorityQuery = DEF_INSERT_GROUP_AUTHORITY_QUERY;

	private String deleteGroupQuery = DEF_DELETE_GROUP_QUERY;

	private String deleteGroupAuthoritiesQuery = DEF_DELETE_GROUP_AUTHORITIES_QUERY;

	private String deleteGroupMembersQuery = DEF_DELETE_GROUP_MEMBERS_QUERY;

	private String renameGroupQuery = DEF_RENAME_GROUP_QUERY;

	private String insertGroupMemberQuery = DEF_INSERT_GROUP_MEMBER_QUERY;

	private String deleteGroupMemberQuery = DEF_DELETE_GROUP_MEMBER_QUERY;

	private String groupAuthoritiesQuery = DEF_GROUP_AUTHORITIES_QUERY_QUERY;

	private String deleteGroupAuthorityQuery = DEF_DELETE_GROUP_AUTHORITY_QUERY;

	private AuthenticationManager authenticationManager;

	private UserCache userCache = new NullUserCache();

	public JdbcUserPasswordDetailsManager() {
	}

	public JdbcUserPasswordDetailsManager(DataSource dataSource) {
		setDataSource(dataSource);
	}

	protected void initDao() throws ApplicationContextException {
		if (this.authenticationManager == null) {
			this.logger.info(
					"No authentication manager set. Reauthentication of users when changing passwords will not be performed.");
		}
		super.initDao();
	}

	/**
	 * Executes the SQL <tt>usersByUsernameQuery</tt> and returns a list of UserDetails
	 * objects. There should normally only be one matching user.
	 */
	@Override
	protected List<UserDetails> loadUsersByUsername(String username) {
		return getJdbcTemplate().query(getUsersByUsernameQuery(), this::mapToUser, username);
	}

	private UserDetails mapToUser(ResultSet rs, int rowNum) throws SQLException {
		String userName = rs.getString(1);
		String password = rs.getString(2);
		boolean enabled = rs.getBoolean(3);
		boolean accLocked = false;
		boolean accExpired = false;
		boolean credsExpired = false;
		if (rs.getMetaData().getColumnCount() > 3) {
			// NOTE: acc_locked, acc_expired and creds_expired are also to be loaded
			accLocked = rs.getBoolean(4);
			accExpired = rs.getBoolean(5);
			credsExpired = rs.getBoolean(6);
		}
		return new User(userName, password, enabled, !accExpired, !credsExpired, !accLocked,
				AuthorityUtils.NO_AUTHORITIES);
	}

	public void createUser(final UserDetails user) {
		validateUserDetails(user);
		getJdbcTemplate().update(this.createUserQuery, (ps) -> {
			ps.setString(1, user.getUsername());
			ps.setString(2, user.getPassword());
			ps.setBoolean(3, user.isEnabled());
			int paramCount = ps.getParameterMetaData().getParameterCount();
			if (paramCount > 3) {
				// NOTE: acc_locked, acc_expired and creds_expired are also to be inserted
				ps.setBoolean(4, !user.isAccountNonLocked());
				ps.setBoolean(5, !user.isAccountNonExpired());
				ps.setBoolean(6, !user.isCredentialsNonExpired());
			}
		});
		if (getEnableAuthorities()) {
			insertUserAuthorities(user);
		}
	}

	public void updateUser(final UserDetails user) {
		validateUserDetails(user);
		getJdbcTemplate().update(this.updateUserQuery, (ps) -> {
			ps.setString(1, user.getPassword());
			ps.setBoolean(2, user.isEnabled());
			int paramCount = ps.getParameterMetaData().getParameterCount();
			if (paramCount == 3) {
				ps.setString(3, user.getUsername());
			}
			else {
				// NOTE: acc_locked, acc_expired and creds_expired are also updated
				ps.setBoolean(3, !user.isAccountNonLocked());
				ps.setBoolean(4, !user.isAccountNonExpired());
				ps.setBoolean(5, !user.isCredentialsNonExpired());
				ps.setString(6, user.getUsername());
			}
		});
		if (getEnableAuthorities()) {
			deleteUserAuthorities(user.getUsername());
			insertUserAuthorities(user);
		}
		this.userCache.removeUserFromCache(user.getUsername());
	}

	private void insertUserAuthorities(UserDetails user) {
		for (GrantedAuthority auth : user.getAuthorities()) {
			getJdbcTemplate().update(this.createAuthorityQuery, user.getUsername(), auth.getAuthority());
		}
	}

	public void deleteUser(String username) {
		if (getEnableAuthorities()) {
			deleteUserAuthorities(username);
		}
		getJdbcTemplate().update(this.deleteUserQuery, username);
		this.userCache.removeUserFromCache(username);
	}

	private void deleteUserAuthorities(String username) {
		getJdbcTemplate().update(this.deleteUserAuthoritiesQuery, username);
	}

	public void changePassword(String oldPassword, String newPassword) throws AuthenticationException {
		Authentication currentUser = this.securityContextHolderStrategy.getContext().getAuthentication();
		if (currentUser == null) {
			// This would indicate bad coding somewhere
			throw new AccessDeniedException(
					"Can't change password as no Authentication object found in context " + "for current user.");
		}
		String username = currentUser.getName();
		// If an authentication manager has been set, re-authenticate the user with the
		// supplied password.
		if (this.authenticationManager != null) {
			this.logger.debug(LogMessage.format("Reauthenticating user '%s' for password change request.", username));
			this.authenticationManager
					.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(username, oldPassword));
		}
		else {
			this.logger.debug("No authentication manager set. Password won't be re-checked.");
		}
		this.logger.debug("Changing password for user '" + username + "'");
		getJdbcTemplate().update(this.changePasswordQuery, newPassword, username);
		Authentication authentication = createNewAuthentication(currentUser, newPassword);
		SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
		context.setAuthentication(authentication);
		this.securityContextHolderStrategy.setContext(context);
		this.userCache.removeUserFromCache(username);
	}

	protected Authentication createNewAuthentication(Authentication currentAuth, String newPassword) {
		UserDetails user = loadUserByUsername(currentAuth.getName());
		UsernamePasswordAuthenticationToken newAuthentication = UsernamePasswordAuthenticationToken.authenticated(user,
				null, user.getAuthorities());
		newAuthentication.setDetails(currentAuth.getDetails());
		return newAuthentication;
	}

	@Override
	public boolean userExists(String username) {
		List<String> users = getJdbcTemplate().queryForList(this.userExistsQuery, new String[] { username },
				String.class);
		if (users.size() > 1) {
			throw new IncorrectResultSizeDataAccessException("More than one user found with name '" + username + "'",
					1);
		}
		return users.size() == 1;
	}

	@Override
	public List<String> findAllGroups() {
		return getJdbcTemplate().queryForList(this.findAllGroupsQuery, String.class);
	}

	@Override
	public List<String> findUsersInGroup(String groupName) {
		Assert.hasText(groupName, "groupName should have text");
		return getJdbcTemplate().queryForList(this.findUsersInGroupQuery, new String[] { groupName }, String.class);
	}

	@Override
	public void createGroup(final String groupName, final List<GrantedAuthority> authorities) {
		Assert.hasText(groupName, "groupName should have text");
		Assert.notNull(authorities, "authorities cannot be null");
		this.logger.debug("Creating new group '" + groupName + "' with authorities "
				+ AuthorityUtils.authorityListToSet(authorities));
		getJdbcTemplate().update(this.insertGroupQuery, groupName);
		int groupId = findGroupId(groupName);
		for (GrantedAuthority a : authorities) {
			String authority = a.getAuthority();
			getJdbcTemplate().update(this.insertGroupAuthorityQuery, (ps) -> {
				ps.setInt(1, groupId);
				ps.setString(2, authority);
			});
		}
	}

	@Override
	public void deleteGroup(String groupName) {
		this.logger.debug("Deleting group '" + groupName + "'");
		Assert.hasText(groupName, "groupName should have text");
		int id = findGroupId(groupName);
		PreparedStatementSetter groupIdPSS = (ps) -> ps.setInt(1, id);
		getJdbcTemplate().update(this.deleteGroupMembersQuery, groupIdPSS);
		getJdbcTemplate().update(this.deleteGroupAuthoritiesQuery, groupIdPSS);
		getJdbcTemplate().update(this.deleteGroupQuery, groupIdPSS);
	}

	@Override
	public void renameGroup(String oldName, String newName) {
		this.logger.debug("Changing group name from '" + oldName + "' to '" + newName + "'");
		Assert.hasText(oldName, "oldName should have text");
		Assert.hasText(newName, "newName should have text");
		getJdbcTemplate().update(this.renameGroupQuery, newName, oldName);
	}

	@Override
	public void addUserToGroup(final String username, final String groupName) {
		this.logger.debug("Adding user '" + username + "' to group '" + groupName + "'");
		Assert.hasText(username, "username should have text");
		Assert.hasText(groupName, "groupName should have text");
		int id = findGroupId(groupName);
		getJdbcTemplate().update(this.insertGroupMemberQuery, (ps) -> {
			ps.setInt(1, id);
			ps.setString(2, username);
		});
		this.userCache.removeUserFromCache(username);
	}

	@Override
	public void removeUserFromGroup(final String username, final String groupName) {
		this.logger.debug("Removing user '" + username + "' to group '" + groupName + "'");
		Assert.hasText(username, "username should have text");
		Assert.hasText(groupName, "groupName should have text");
		int id = findGroupId(groupName);
		getJdbcTemplate().update(this.deleteGroupMemberQuery, (ps) -> {
			ps.setInt(1, id);
			ps.setString(2, username);
		});
		this.userCache.removeUserFromCache(username);
	}

	@Override
	public List<GrantedAuthority> findGroupAuthorities(String groupName) {
		this.logger.debug("Loading authorities for group '" + groupName + "'");
		Assert.hasText(groupName, "groupName should have text");
		return getJdbcTemplate().query(this.groupAuthoritiesQuery, new String[] { groupName },
				this::mapToGrantedAuthority);
	}

	private GrantedAuthority mapToGrantedAuthority(ResultSet rs, int rowNum) throws SQLException {
		String roleName = getRolePrefix() + rs.getString(3);
		return new SimpleGrantedAuthority(roleName);
	}

	@Override
	public void removeGroupAuthority(String groupName, final GrantedAuthority authority) {
		this.logger.debug("Removing authority '" + authority + "' from group '" + groupName + "'");
		Assert.hasText(groupName, "groupName should have text");
		Assert.notNull(authority, "authority cannot be null");
		int id = findGroupId(groupName);
		getJdbcTemplate().update(this.deleteGroupAuthorityQuery, (ps) -> {
			ps.setInt(1, id);
			ps.setString(2, authority.getAuthority());
		});
	}

	@Override
	public void addGroupAuthority(final String groupName, final GrantedAuthority authority) {
		this.logger.debug("Adding authority '" + authority + "' to group '" + groupName + "'");
		Assert.hasText(groupName, "groupName should have text");
		Assert.notNull(authority, "authority cannot be null");
		int id = findGroupId(groupName);
		getJdbcTemplate().update(this.insertGroupAuthorityQuery, (ps) -> {
			ps.setInt(1, id);
			ps.setString(2, authority.getAuthority());
		});
	}

	private int findGroupId(String group) {
		return getJdbcTemplate().queryForObject(this.findGroupIdQuery, Integer.class, group);
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	public void setCreateUserQuery(String createUserQuery) {
		Assert.hasText(createUserQuery, "createUserQuery should have text");
		this.createUserQuery = createUserQuery;
	}

	public void setDeleteUserQuery(String deleteUserQuery) {
		Assert.hasText(deleteUserQuery, "deleteUserQuery should have text");
		this.deleteUserQuery = deleteUserQuery;
	}

	public void setUpdateUserQuery(String updateUserQuery) {
		Assert.hasText(updateUserQuery, "updateUserQuery should have text");
		this.updateUserQuery = updateUserQuery;
	}

	public void setCreateAuthorityQuery(String createAuthorityQuery) {
		Assert.hasText(createAuthorityQuery, "createAuthorityQuery should have text");
		this.createAuthorityQuery = createAuthorityQuery;
	}

	public void setDeleteUserAuthoritiesQuery(String deleteUserAuthoritiesQuery) {
		Assert.hasText(deleteUserAuthoritiesQuery, "deleteUserAuthoritiesQuery should have text");
		this.deleteUserAuthoritiesQuery = deleteUserAuthoritiesQuery;
	}

	public void setUserExistsQuery(String userExistsQuery) {
		Assert.hasText(userExistsQuery, "userExistsQuery should have text");
		this.userExistsQuery = userExistsQuery;
	}

	public void setChangePasswordQuery(String changePasswordQuery) {
		Assert.hasText(changePasswordQuery, "changePasswordQuery should have text");
		this.changePasswordQuery = changePasswordQuery;
	}

	public void setFindAllGroupsQuery(String findAllGroupsQuery) {
		Assert.hasText(findAllGroupsQuery, "findAllGroupsQuery should have text");
		this.findAllGroupsQuery = findAllGroupsQuery;
	}

	public void setFindUsersInGroupQuery(String findUsersInGroupQuery) {
		Assert.hasText(findUsersInGroupQuery, "findUsersInGroupQuery should have text");
		this.findUsersInGroupQuery = findUsersInGroupQuery;
	}

	public void setInsertGroupQuery(String insertGroupQuery) {
		Assert.hasText(insertGroupQuery, "insertGroupQuery should have text");
		this.insertGroupQuery = insertGroupQuery;
	}

	public void setFindGroupIdQuery(String findGroupIdQuery) {
		Assert.hasText(findGroupIdQuery, "findGroupIdQuery should have text");
		this.findGroupIdQuery = findGroupIdQuery;
	}

	public void setInsertGroupAuthorityQuery(String insertGroupAuthorityQuery) {
		Assert.hasText(insertGroupAuthorityQuery, "insertGroupAuthorityQuery should have text");
		this.insertGroupAuthorityQuery = insertGroupAuthorityQuery;
	}

	public void setDeleteGroupQuery(String deleteGroupQuery) {
		Assert.hasText(deleteGroupQuery, "deleteGroupQuery should have text");
		this.deleteGroupQuery = deleteGroupQuery;
	}

	public void setDeleteGroupAuthoritiesQuery(String deleteGroupAuthoritiesQuery) {
		Assert.hasText(deleteGroupAuthoritiesQuery, "deleteGroupAuthoritiesQuery should have text");
		this.deleteGroupAuthoritiesQuery = deleteGroupAuthoritiesQuery;
	}

	public void setDeleteGroupMembersQuery(String deleteGroupMembersQuery) {
		Assert.hasText(deleteGroupMembersQuery, "deleteGroupMembersQuery should have text");
		this.deleteGroupMembersQuery = deleteGroupMembersQuery;
	}

	public void setRenameGroupQuery(String renameGroupQuery) {
		Assert.hasText(renameGroupQuery, "renameGroupQuery should have text");
		this.renameGroupQuery = renameGroupQuery;
	}

	public void setInsertGroupMemberQuery(String insertGroupMemberQuery) {
		Assert.hasText(insertGroupMemberQuery, "insertGroupMemberQuery should have text");
		this.insertGroupMemberQuery = insertGroupMemberQuery;
	}

	public void setDeleteGroupMemberQuery(String deleteGroupMemberQuery) {
		Assert.hasText(deleteGroupMemberQuery, "deleteGroupMemberQuery should have text");
		this.deleteGroupMemberQuery = deleteGroupMemberQuery;
	}

	public void setGroupAuthoritiesQuery(String groupAuthoritiesQuery) {
		Assert.hasText(groupAuthoritiesQuery, "groupAuthoritiesQuery should have text");
		this.groupAuthoritiesQuery = groupAuthoritiesQuery;
	}

	public void setDeleteGroupAuthorityQuery(String deleteGroupAuthorityQuery) {
		Assert.hasText(deleteGroupAuthorityQuery, "deleteGroupAuthorityQuery should have text");
		this.deleteGroupAuthorityQuery = deleteGroupAuthorityQuery;
	}

	/**
	 * Optionally sets the UserCache if one is in use in the application. This allows the
	 * user to be removed from the cache after updates have taken place to avoid stale
	 * data.
	 * @param userCache the cache used by the AuthenticationManager.
	 */
	public void setUserCache(UserCache userCache) {
		Assert.notNull(userCache, "userCache cannot be null");
		this.userCache = userCache;
	}

	private void validateUserDetails(UserDetails user) {
		Assert.hasText(user.getUsername(), "Username may not be empty or null");
		validateAuthorities(user.getAuthorities());
	}

	private void validateAuthorities(Collection<? extends GrantedAuthority> authorities) {
		Assert.notNull(authorities, "Authorities list must not be null");
		for (GrantedAuthority authority : authorities) {
			Assert.notNull(authority, "Authorities list contains a null entry");
			Assert.hasText(authority.getAuthority(), "getAuthority() method must return a non-empty string");
		}
	}

	@Override
	public UserDetails updatePassword(UserDetails user, String newPassword) {
		this.logger.debug("Updating password for user '" + user.getUsername() + "'");
		getJdbcTemplate().update(this.changePasswordQuery, newPassword, user.getUsername());
		this.userCache.removeUserFromCache(user.getUsername());
		return User.withUserDetails(user).password(newPassword).build();
	}
}
