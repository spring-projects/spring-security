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

package org.springframework.security.provisioning;

import java.util.Collection;
import java.util.List;

import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContextException;
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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.util.Assert;

/**
 * Jdbc user management service, based on the same table structure as its parent class,
 * <tt>JdbcDaoImpl</tt>.
 * <p>
 * Provides CRUD operations for both users and groups. Note that if the
 * {@link #setEnableAuthorities(boolean) enableAuthorities} property is set to false,
 * calls to createUser, updateUser and deleteUser will not store the authorities from the
 * <tt>UserDetails</tt> or delete authorities for the user. Since this class cannot
 * differentiate between authorities which were loaded for an individual or for a group of
 * which the individual is a member, it's important that you take this into account when
 * using this implementation for managing your users.
 *
 * @author Luke Taylor
 * @since 2.0
 */
public class JdbcUserDetailsManager extends JdbcDaoImpl implements UserDetailsManager, GroupManager {

	// UserDetailsManager SQL
	public static final String DEF_CREATE_USER_SQL = "insert into users (username, password, enabled) values (?,?,?)";

	public static final String DEF_DELETE_USER_SQL = "delete from users where username = ?";

	public static final String DEF_UPDATE_USER_SQL = "update users set password = ?, enabled = ? where username = ?";

	public static final String DEF_INSERT_AUTHORITY_SQL = "insert into authorities (username, authority) values (?,?)";

	public static final String DEF_DELETE_USER_AUTHORITIES_SQL = "delete from authorities where username = ?";

	public static final String DEF_USER_EXISTS_SQL = "select username from users where username = ?";

	public static final String DEF_CHANGE_PASSWORD_SQL = "update users set password = ? where username = ?";

	// GroupManager SQL
	public static final String DEF_FIND_GROUPS_SQL = "select group_name from groups";

	public static final String DEF_FIND_USERS_IN_GROUP_SQL = "select username from group_members gm, groups g "
			+ "where gm.group_id = g.id and g.group_name = ?";

	public static final String DEF_INSERT_GROUP_SQL = "insert into groups (group_name) values (?)";

	public static final String DEF_FIND_GROUP_ID_SQL = "select id from groups where group_name = ?";

	public static final String DEF_INSERT_GROUP_AUTHORITY_SQL = "insert into group_authorities (group_id, authority) values (?,?)";

	public static final String DEF_DELETE_GROUP_SQL = "delete from groups where id = ?";

	public static final String DEF_DELETE_GROUP_AUTHORITIES_SQL = "delete from group_authorities where group_id = ?";

	public static final String DEF_DELETE_GROUP_MEMBERS_SQL = "delete from group_members where group_id = ?";

	public static final String DEF_RENAME_GROUP_SQL = "update groups set group_name = ? where group_name = ?";

	public static final String DEF_INSERT_GROUP_MEMBER_SQL = "insert into group_members (group_id, username) values (?,?)";

	public static final String DEF_DELETE_GROUP_MEMBER_SQL = "delete from group_members where group_id = ? and username = ?";

	public static final String DEF_GROUP_AUTHORITIES_QUERY_SQL = "select g.id, g.group_name, ga.authority "
			+ "from groups g, group_authorities ga " + "where g.group_name = ? " + "and g.id = ga.group_id ";

	public static final String DEF_DELETE_GROUP_AUTHORITY_SQL = "delete from group_authorities where group_id = ? and authority = ?";

	protected final Log logger = LogFactory.getLog(getClass());

	private String createUserSql = DEF_CREATE_USER_SQL;

	private String deleteUserSql = DEF_DELETE_USER_SQL;

	private String updateUserSql = DEF_UPDATE_USER_SQL;

	private String createAuthoritySql = DEF_INSERT_AUTHORITY_SQL;

	private String deleteUserAuthoritiesSql = DEF_DELETE_USER_AUTHORITIES_SQL;

	private String userExistsSql = DEF_USER_EXISTS_SQL;

	private String changePasswordSql = DEF_CHANGE_PASSWORD_SQL;

	private String findAllGroupsSql = DEF_FIND_GROUPS_SQL;

	private String findUsersInGroupSql = DEF_FIND_USERS_IN_GROUP_SQL;

	private String insertGroupSql = DEF_INSERT_GROUP_SQL;

	private String findGroupIdSql = DEF_FIND_GROUP_ID_SQL;

	private String insertGroupAuthoritySql = DEF_INSERT_GROUP_AUTHORITY_SQL;

	private String deleteGroupSql = DEF_DELETE_GROUP_SQL;

	private String deleteGroupAuthoritiesSql = DEF_DELETE_GROUP_AUTHORITIES_SQL;

	private String deleteGroupMembersSql = DEF_DELETE_GROUP_MEMBERS_SQL;

	private String renameGroupSql = DEF_RENAME_GROUP_SQL;

	private String insertGroupMemberSql = DEF_INSERT_GROUP_MEMBER_SQL;

	private String deleteGroupMemberSql = DEF_DELETE_GROUP_MEMBER_SQL;

	private String groupAuthoritiesSql = DEF_GROUP_AUTHORITIES_QUERY_SQL;

	private String deleteGroupAuthoritySql = DEF_DELETE_GROUP_AUTHORITY_SQL;

	private AuthenticationManager authenticationManager;

	private UserCache userCache = new NullUserCache();

	public JdbcUserDetailsManager() {
	}

	public JdbcUserDetailsManager(DataSource dataSource) {
		setDataSource(dataSource);
	}

	@Override
	protected void initDao() throws ApplicationContextException {
		if (this.authenticationManager == null) {
			this.logger.info("No authentication manager set. Reauthentication of users when changing passwords will "
					+ "not be performed.");
		}

		super.initDao();
	}

	/**
	 * Executes the SQL <tt>usersByUsernameQuery</tt> and returns a list of UserDetails
	 * objects. There should normally only be one matching user.
	 */
	@Override
	protected List<UserDetails> loadUsersByUsername(String username) {
		return getJdbcTemplate().query(getUsersByUsernameQuery(), new String[] { username }, (rs, rowNum) -> {

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
		});
	}

	@Override
	public void createUser(final UserDetails user) {
		validateUserDetails(user);

		getJdbcTemplate().update(this.createUserSql, ps -> {
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

	@Override
	public void updateUser(final UserDetails user) {
		validateUserDetails(user);

		getJdbcTemplate().update(this.updateUserSql, ps -> {
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
			getJdbcTemplate().update(this.createAuthoritySql, user.getUsername(), auth.getAuthority());
		}
	}

	@Override
	public void deleteUser(String username) {
		if (getEnableAuthorities()) {
			deleteUserAuthorities(username);
		}
		getJdbcTemplate().update(this.deleteUserSql, username);
		this.userCache.removeUserFromCache(username);
	}

	private void deleteUserAuthorities(String username) {
		getJdbcTemplate().update(this.deleteUserAuthoritiesSql, username);
	}

	@Override
	public void changePassword(String oldPassword, String newPassword) throws AuthenticationException {
		Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();

		if (currentUser == null) {
			// This would indicate bad coding somewhere
			throw new AccessDeniedException(
					"Can't change password as no Authentication object found in context " + "for current user.");
		}

		String username = currentUser.getName();

		// If an authentication manager has been set, re-authenticate the user with the
		// supplied password.
		if (this.authenticationManager != null) {
			this.logger.debug("Reauthenticating user '" + username + "' for password change request.");

			this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, oldPassword));
		}
		else {
			this.logger.debug("No authentication manager set. Password won't be re-checked.");
		}

		this.logger.debug("Changing password for user '" + username + "'");

		getJdbcTemplate().update(this.changePasswordSql, newPassword, username);

		SecurityContextHolder.getContext().setAuthentication(createNewAuthentication(currentUser, newPassword));

		this.userCache.removeUserFromCache(username);
	}

	protected Authentication createNewAuthentication(Authentication currentAuth, String newPassword) {
		UserDetails user = loadUserByUsername(currentAuth.getName());

		UsernamePasswordAuthenticationToken newAuthentication = new UsernamePasswordAuthenticationToken(user, null,
				user.getAuthorities());
		newAuthentication.setDetails(currentAuth.getDetails());

		return newAuthentication;
	}

	@Override
	public boolean userExists(String username) {
		List<String> users = getJdbcTemplate().queryForList(this.userExistsSql, new String[] { username },
				String.class);

		if (users.size() > 1) {
			throw new IncorrectResultSizeDataAccessException("More than one user found with name '" + username + "'",
					1);
		}

		return users.size() == 1;
	}

	@Override
	public List<String> findAllGroups() {
		return getJdbcTemplate().queryForList(this.findAllGroupsSql, String.class);
	}

	@Override
	public List<String> findUsersInGroup(String groupName) {
		Assert.hasText(groupName, "groupName should have text");
		return getJdbcTemplate().queryForList(this.findUsersInGroupSql, new String[] { groupName }, String.class);
	}

	@Override
	public void createGroup(final String groupName, final List<GrantedAuthority> authorities) {
		Assert.hasText(groupName, "groupName should have text");
		Assert.notNull(authorities, "authorities cannot be null");

		this.logger.debug("Creating new group '" + groupName + "' with authorities "
				+ AuthorityUtils.authorityListToSet(authorities));

		getJdbcTemplate().update(this.insertGroupSql, groupName);

		final int groupId = findGroupId(groupName);

		for (GrantedAuthority a : authorities) {
			final String authority = a.getAuthority();
			getJdbcTemplate().update(this.insertGroupAuthoritySql, ps -> {
				ps.setInt(1, groupId);
				ps.setString(2, authority);
			});
		}
	}

	@Override
	public void deleteGroup(String groupName) {
		this.logger.debug("Deleting group '" + groupName + "'");
		Assert.hasText(groupName, "groupName should have text");

		final int id = findGroupId(groupName);
		PreparedStatementSetter groupIdPSS = ps -> ps.setInt(1, id);
		getJdbcTemplate().update(this.deleteGroupMembersSql, groupIdPSS);
		getJdbcTemplate().update(this.deleteGroupAuthoritiesSql, groupIdPSS);
		getJdbcTemplate().update(this.deleteGroupSql, groupIdPSS);
	}

	@Override
	public void renameGroup(String oldName, String newName) {
		this.logger.debug("Changing group name from '" + oldName + "' to '" + newName + "'");
		Assert.hasText(oldName, "oldName should have text");
		Assert.hasText(newName, "newName should have text");

		getJdbcTemplate().update(this.renameGroupSql, newName, oldName);
	}

	@Override
	public void addUserToGroup(final String username, final String groupName) {
		this.logger.debug("Adding user '" + username + "' to group '" + groupName + "'");
		Assert.hasText(username, "username should have text");
		Assert.hasText(groupName, "groupName should have text");

		final int id = findGroupId(groupName);
		getJdbcTemplate().update(this.insertGroupMemberSql, ps -> {
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

		final int id = findGroupId(groupName);

		getJdbcTemplate().update(this.deleteGroupMemberSql, ps -> {
			ps.setInt(1, id);
			ps.setString(2, username);
		});

		this.userCache.removeUserFromCache(username);
	}

	@Override
	public List<GrantedAuthority> findGroupAuthorities(String groupName) {
		this.logger.debug("Loading authorities for group '" + groupName + "'");
		Assert.hasText(groupName, "groupName should have text");

		return getJdbcTemplate().query(this.groupAuthoritiesSql, new String[] { groupName }, (rs, rowNum) -> {
			String roleName = getRolePrefix() + rs.getString(3);

			return new SimpleGrantedAuthority(roleName);
		});
	}

	@Override
	public void removeGroupAuthority(String groupName, final GrantedAuthority authority) {
		this.logger.debug("Removing authority '" + authority + "' from group '" + groupName + "'");
		Assert.hasText(groupName, "groupName should have text");
		Assert.notNull(authority, "authority cannot be null");

		final int id = findGroupId(groupName);

		getJdbcTemplate().update(this.deleteGroupAuthoritySql, ps -> {
			ps.setInt(1, id);
			ps.setString(2, authority.getAuthority());
		});
	}

	@Override
	public void addGroupAuthority(final String groupName, final GrantedAuthority authority) {
		this.logger.debug("Adding authority '" + authority + "' to group '" + groupName + "'");
		Assert.hasText(groupName, "groupName should have text");
		Assert.notNull(authority, "authority cannot be null");

		final int id = findGroupId(groupName);
		getJdbcTemplate().update(this.insertGroupAuthoritySql, ps -> {
			ps.setInt(1, id);
			ps.setString(2, authority.getAuthority());
		});
	}

	private int findGroupId(String group) {
		return getJdbcTemplate().queryForObject(this.findGroupIdSql, Integer.class, group);
	}

	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	public void setCreateUserSql(String createUserSql) {
		Assert.hasText(createUserSql, "createUserSql should have text");
		this.createUserSql = createUserSql;
	}

	public void setDeleteUserSql(String deleteUserSql) {
		Assert.hasText(deleteUserSql, "deleteUserSql should have text");
		this.deleteUserSql = deleteUserSql;
	}

	public void setUpdateUserSql(String updateUserSql) {
		Assert.hasText(updateUserSql, "updateUserSql should have text");
		this.updateUserSql = updateUserSql;
	}

	public void setCreateAuthoritySql(String createAuthoritySql) {
		Assert.hasText(createAuthoritySql, "createAuthoritySql should have text");
		this.createAuthoritySql = createAuthoritySql;
	}

	public void setDeleteUserAuthoritiesSql(String deleteUserAuthoritiesSql) {
		Assert.hasText(deleteUserAuthoritiesSql, "deleteUserAuthoritiesSql should have text");
		this.deleteUserAuthoritiesSql = deleteUserAuthoritiesSql;
	}

	public void setUserExistsSql(String userExistsSql) {
		Assert.hasText(userExistsSql, "userExistsSql should have text");
		this.userExistsSql = userExistsSql;
	}

	public void setChangePasswordSql(String changePasswordSql) {
		Assert.hasText(changePasswordSql, "changePasswordSql should have text");
		this.changePasswordSql = changePasswordSql;
	}

	public void setFindAllGroupsSql(String findAllGroupsSql) {
		Assert.hasText(findAllGroupsSql, "findAllGroupsSql should have text");
		this.findAllGroupsSql = findAllGroupsSql;
	}

	public void setFindUsersInGroupSql(String findUsersInGroupSql) {
		Assert.hasText(findUsersInGroupSql, "findUsersInGroupSql should have text");
		this.findUsersInGroupSql = findUsersInGroupSql;
	}

	public void setInsertGroupSql(String insertGroupSql) {
		Assert.hasText(insertGroupSql, "insertGroupSql should have text");
		this.insertGroupSql = insertGroupSql;
	}

	public void setFindGroupIdSql(String findGroupIdSql) {
		Assert.hasText(findGroupIdSql, "findGroupIdSql should have text");
		this.findGroupIdSql = findGroupIdSql;
	}

	public void setInsertGroupAuthoritySql(String insertGroupAuthoritySql) {
		Assert.hasText(insertGroupAuthoritySql, "insertGroupAuthoritySql should have text");
		this.insertGroupAuthoritySql = insertGroupAuthoritySql;
	}

	public void setDeleteGroupSql(String deleteGroupSql) {
		Assert.hasText(deleteGroupSql, "deleteGroupSql should have text");
		this.deleteGroupSql = deleteGroupSql;
	}

	public void setDeleteGroupAuthoritiesSql(String deleteGroupAuthoritiesSql) {
		Assert.hasText(deleteGroupAuthoritiesSql, "deleteGroupAuthoritiesSql should have text");
		this.deleteGroupAuthoritiesSql = deleteGroupAuthoritiesSql;
	}

	public void setDeleteGroupMembersSql(String deleteGroupMembersSql) {
		Assert.hasText(deleteGroupMembersSql, "deleteGroupMembersSql should have text");
		this.deleteGroupMembersSql = deleteGroupMembersSql;
	}

	public void setRenameGroupSql(String renameGroupSql) {
		Assert.hasText(renameGroupSql, "renameGroupSql should have text");
		this.renameGroupSql = renameGroupSql;
	}

	public void setInsertGroupMemberSql(String insertGroupMemberSql) {
		Assert.hasText(insertGroupMemberSql, "insertGroupMemberSql should have text");
		this.insertGroupMemberSql = insertGroupMemberSql;
	}

	public void setDeleteGroupMemberSql(String deleteGroupMemberSql) {
		Assert.hasText(deleteGroupMemberSql, "deleteGroupMemberSql should have text");
		this.deleteGroupMemberSql = deleteGroupMemberSql;
	}

	public void setGroupAuthoritiesSql(String groupAuthoritiesSql) {
		Assert.hasText(groupAuthoritiesSql, "groupAuthoritiesSql should have text");
		this.groupAuthoritiesSql = groupAuthoritiesSql;
	}

	public void setDeleteGroupAuthoritySql(String deleteGroupAuthoritySql) {
		Assert.hasText(deleteGroupAuthoritySql, "deleteGroupAuthoritySql should have text");
		this.deleteGroupAuthoritySql = deleteGroupAuthoritySql;
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

}
