/*
 * Copyright 2002-2022 the original author or authors.
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

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.PopulatedDatabase;
import org.springframework.security.TestDataSource;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link JdbcUserDetailsManager}
 *
 * @author Luke Taylor
 */
public class JdbcUserDetailsManagerTests {

	private static final String SELECT_JOE_SQL = "select * from users where username = 'joe'";

	private static final String SELECT_JOE_AUTHORITIES_SQL = "select * from authorities where username = 'joe'";

	private static final UserDetails joe = new User("joe", "password", true, true, true, true,
			AuthorityUtils.createAuthorityList("A", "C", "B"));

	private static TestDataSource dataSource;

	private JdbcUserDetailsManager manager;

	private MockUserCache cache;

	private JdbcTemplate template;

	@BeforeAll
	public static void createDataSource() {
		dataSource = new TestDataSource("jdbcusermgrtest");
	}

	@AfterAll
	public static void clearDataSource() throws Exception {
		dataSource.destroy();
		dataSource = null;
	}

	@BeforeEach
	public void initializeManagerAndCreateTables() {
		this.manager = new JdbcUserDetailsManager();
		this.cache = new MockUserCache();
		this.manager.setUserCache(this.cache);
		this.manager.setDataSource(dataSource);
		this.manager.setCreateUserSql(JdbcUserDetailsManager.DEF_CREATE_USER_SQL);
		this.manager.setUpdateUserSql(JdbcUserDetailsManager.DEF_UPDATE_USER_SQL);
		this.manager.setUserExistsSql(JdbcUserDetailsManager.DEF_USER_EXISTS_SQL);
		this.manager.setCreateAuthoritySql(JdbcUserDetailsManager.DEF_INSERT_AUTHORITY_SQL);
		this.manager.setDeleteUserAuthoritiesSql(JdbcUserDetailsManager.DEF_DELETE_USER_AUTHORITIES_SQL);
		this.manager.setDeleteUserSql(JdbcUserDetailsManager.DEF_DELETE_USER_SQL);
		this.manager.setChangePasswordSql(JdbcUserDetailsManager.DEF_CHANGE_PASSWORD_SQL);
		this.manager.initDao();
		this.template = this.manager.getJdbcTemplate();
		this.template.execute("create table users(username varchar(20) not null primary key,"
				+ "password varchar(20) not null, enabled boolean not null)");
		this.template
				.execute("create table authorities (username varchar(20) not null, authority varchar(20) not null, "
						+ "constraint fk_authorities_users foreign key(username) references users(username))");
		PopulatedDatabase.createGroupTables(this.template);
		PopulatedDatabase.insertGroupData(this.template);
	}

	@AfterEach
	public void dropTablesAndClearContext() {
		this.template.execute("drop table authorities");
		this.template.execute("drop table users");
		this.template.execute("drop table group_authorities");
		this.template.execute("drop table group_members");
		this.template.execute("drop table groups");
		SecurityContextHolder.clearContext();
	}

	private void setUpAccLockingColumns() {
		this.template.execute("alter table users add column acc_locked boolean default false not null");
		this.template.execute("alter table users add column acc_expired boolean default false not null");
		this.template.execute("alter table users add column creds_expired boolean default false not null");
		this.manager.setUsersByUsernameQuery(
				"select username,password,enabled, acc_locked, acc_expired, creds_expired from users where username = ?");
		this.manager.setCreateUserSql(
				"insert into users (username, password, enabled, acc_locked, acc_expired, creds_expired) values (?,?,?,?,?,?)");
		this.manager.setUpdateUserSql(
				"update users set password = ?, enabled = ?, acc_locked=?, acc_expired=?, creds_expired=? where username = ?");
	}

	@Test
	public void createUserInsertsCorrectData() {
		this.manager.createUser(joe);
		UserDetails joe2 = this.manager.loadUserByUsername("joe");
		assertThat(joe2).isEqualTo(joe);
	}

	@Test
	public void createUserInsertsCorrectDataWithLocking() {
		setUpAccLockingColumns();
		UserDetails user = new User("joe", "pass", true, false, true, false,
				AuthorityUtils.createAuthorityList("A", "B"));
		this.manager.createUser(user);
		UserDetails user2 = this.manager.loadUserByUsername(user.getUsername());
		assertThat(user2).isEqualToComparingFieldByField(user);
	}

	@Test
	public void deleteUserRemovesUserDataAndAuthoritiesAndClearsCache() {
		insertJoe();
		this.manager.deleteUser("joe");
		assertThat(this.template.queryForList(SELECT_JOE_SQL)).isEmpty();
		assertThat(this.template.queryForList(SELECT_JOE_AUTHORITIES_SQL)).isEmpty();
		assertThat(this.cache.getUserMap().containsKey("joe")).isFalse();
	}

	@Test
	public void updateUserChangesDataCorrectlyAndClearsCache() {
		insertJoe();
		User newJoe = new User("joe", "newpassword", false, true, true, true,
				AuthorityUtils.createAuthorityList(new String[] { "D", "F", "E" }));
		this.manager.updateUser(newJoe);
		UserDetails joe = this.manager.loadUserByUsername("joe");
		assertThat(joe).isEqualTo(newJoe);
		assertThat(this.cache.getUserMap().containsKey("joe")).isFalse();
	}

	@Test
	public void updateUserChangesDataCorrectlyAndClearsCacheWithLocking() {
		setUpAccLockingColumns();
		insertJoe();
		User newJoe = new User("joe", "newpassword", false, false, false, true,
				AuthorityUtils.createAuthorityList("D", "F", "E"));
		this.manager.updateUser(newJoe);
		UserDetails joe = this.manager.loadUserByUsername(newJoe.getUsername());
		assertThat(joe).isEqualToComparingFieldByField(newJoe);
		assertThat(this.cache.getUserMap().containsKey(newJoe.getUsername())).isFalse();
	}

	@Test
	public void userExistsReturnsFalseForNonExistentUsername() {
		assertThat(this.manager.userExists("joe")).isFalse();
	}

	@Test
	public void userExistsReturnsTrueForExistingUsername() {
		insertJoe();
		assertThat(this.manager.userExists("joe")).isTrue();
		assertThat(this.cache.getUserMap().containsKey("joe")).isTrue();
	}

	@Test
	public void changePasswordFailsForUnauthenticatedUser() {
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> this.manager.changePassword("password", "newPassword"));
	}

	@Test
	public void changePasswordSucceedsWithAuthenticatedUserAndNoAuthenticationManagerSet() {
		insertJoe();
		authenticateJoe();
		this.manager.changePassword("wrongpassword", "newPassword");
		UserDetails newJoe = this.manager.loadUserByUsername("joe");
		assertThat(newJoe.getPassword()).isEqualTo("newPassword");
		assertThat(this.cache.getUserMap().containsKey("joe")).isFalse();
	}

	@Test
	public void changePasswordWhenCustomSecurityContextHolderStrategyThenUses() {
		insertJoe();
		Authentication authentication = authenticateJoe();
		SecurityContextHolderStrategy strategy = mock(SecurityContextHolderStrategy.class);
		given(strategy.getContext()).willReturn(new SecurityContextImpl(authentication));
		given(strategy.createEmptyContext()).willReturn(new SecurityContextImpl());
		this.manager.setSecurityContextHolderStrategy(strategy);
		this.manager.changePassword("wrongpassword", "newPassword");
		verify(strategy).getContext();
	}

	@Test
	public void changePasswordSucceedsWithIfReAuthenticationSucceeds() {
		insertJoe();
		Authentication currentAuth = authenticateJoe();
		AuthenticationManager am = mock(AuthenticationManager.class);
		given(am.authenticate(currentAuth)).willReturn(currentAuth);
		this.manager.setAuthenticationManager(am);
		this.manager.changePassword("password", "newPassword");
		UserDetails newJoe = this.manager.loadUserByUsername("joe");
		assertThat(newJoe.getPassword()).isEqualTo("newPassword");
		// The password in the context should also be altered
		Authentication newAuth = SecurityContextHolder.getContext().getAuthentication();
		assertThat(newAuth.getName()).isEqualTo("joe");
		assertThat(newAuth.getDetails()).isEqualTo(currentAuth.getDetails());
		assertThat(newAuth.getCredentials()).isNull();
		assertThat(this.cache.getUserMap().containsKey("joe")).isFalse();
	}

	@Test
	public void changePasswordFailsIfReAuthenticationFails() {
		insertJoe();
		authenticateJoe();
		AuthenticationManager am = mock(AuthenticationManager.class);
		given(am.authenticate(any(Authentication.class))).willThrow(new BadCredentialsException(""));
		this.manager.setAuthenticationManager(am);
		assertThatExceptionOfType(BadCredentialsException.class)
				.isThrownBy(() -> this.manager.changePassword("password", "newPassword"));
		// Check password hasn't changed.
		UserDetails newJoe = this.manager.loadUserByUsername("joe");
		assertThat(newJoe.getPassword()).isEqualTo("password");
		assertThat(SecurityContextHolder.getContext().getAuthentication().getCredentials()).isEqualTo("password");
		assertThat(this.cache.getUserMap().containsKey("joe")).isTrue();
	}

	@Test
	public void findAllGroupsReturnsExpectedGroupNames() {
		List<String> groups = this.manager.findAllGroups();
		assertThat(groups).hasSize(4);
		Collections.sort(groups);
		assertThat(groups.get(0)).isEqualTo("GROUP_0");
		assertThat(groups.get(1)).isEqualTo("GROUP_1");
		assertThat(groups.get(2)).isEqualTo("GROUP_2");
		assertThat(groups.get(3)).isEqualTo("GROUP_3");
	}

	@Test
	public void findGroupMembersReturnsCorrectData() {
		List<String> groupMembers = this.manager.findUsersInGroup("GROUP_0");
		assertThat(groupMembers).hasSize(1);
		assertThat(groupMembers.get(0)).isEqualTo("jerry");
		groupMembers = this.manager.findUsersInGroup("GROUP_1");
		assertThat(groupMembers).hasSize(2);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void createGroupInsertsCorrectData() {
		this.manager.createGroup("TEST_GROUP", AuthorityUtils.createAuthorityList("ROLE_X", "ROLE_Y"));
		List roles = this.template.queryForList("select ga.authority from groups g, group_authorities ga "
				+ "where ga.group_id = g.id " + "and g.group_name = 'TEST_GROUP'");
		assertThat(roles).hasSize(2);
	}

	@Test
	public void deleteGroupRemovesData() {
		this.manager.deleteGroup("GROUP_0");
		this.manager.deleteGroup("GROUP_1");
		this.manager.deleteGroup("GROUP_2");
		this.manager.deleteGroup("GROUP_3");
		assertThat(this.template.queryForList("select * from group_authorities")).isEmpty();
		assertThat(this.template.queryForList("select * from group_members")).isEmpty();
		assertThat(this.template.queryForList("select id from groups")).isEmpty();
	}

	@Test
	public void renameGroupIsSuccessful() {
		this.manager.renameGroup("GROUP_0", "GROUP_X");
		assertThat(this.template.queryForObject("select id from groups where group_name = 'GROUP_X'", Integer.class))
				.isZero();
	}

	@Test
	public void addingGroupUserSetsCorrectData() {
		this.manager.addUserToGroup("tom", "GROUP_0");
		assertThat(this.template.queryForList("select username from group_members where group_id = 0")).hasSize(2);
	}

	@Test
	public void removeUserFromGroupDeletesGroupMemberRow() {
		this.manager.removeUserFromGroup("jerry", "GROUP_1");
		assertThat(this.template.queryForList("select group_id from group_members where username = 'jerry'"))
				.hasSize(1);
	}

	@Test
	public void findGroupAuthoritiesReturnsCorrectAuthorities() {
		assertThat(AuthorityUtils.createAuthorityList("ROLE_A"))
				.isEqualTo(this.manager.findGroupAuthorities("GROUP_0"));
	}

	@Test
	public void addGroupAuthorityInsertsCorrectGroupAuthorityRow() {
		GrantedAuthority auth = new SimpleGrantedAuthority("ROLE_X");
		this.manager.addGroupAuthority("GROUP_0", auth);
		this.template.queryForObject(
				"select authority from group_authorities where authority = 'ROLE_X' and group_id = 0", String.class);
	}

	@Test
	public void deleteGroupAuthorityRemovesCorrectRows() {
		GrantedAuthority auth = new SimpleGrantedAuthority("ROLE_A");
		this.manager.removeGroupAuthority("GROUP_0", auth);
		assertThat(this.template.queryForList("select authority from group_authorities where group_id = 0")).isEmpty();
		this.manager.removeGroupAuthority("GROUP_2", auth);
		assertThat(this.template.queryForList("select authority from group_authorities where group_id = 2")).hasSize(2);
	}

	// SEC-1156
	@Test
	public void createUserDoesNotSaveAuthoritiesIfEnableAuthoritiesIsFalse() {
		this.manager.setEnableAuthorities(false);
		this.manager.createUser(joe);
		assertThat(this.template.queryForList(SELECT_JOE_AUTHORITIES_SQL)).isEmpty();
	}

	// SEC-1156
	@Test
	public void updateUserDoesNotSaveAuthoritiesIfEnableAuthoritiesIsFalse() {
		this.manager.setEnableAuthorities(false);
		insertJoe();
		this.template.execute("delete from authorities where username='joe'");
		this.manager.updateUser(joe);
		assertThat(this.template.queryForList(SELECT_JOE_AUTHORITIES_SQL)).isEmpty();
	}

	// SEC-2166
	@Test
	public void createNewAuthenticationUsesNullPasswordToKeepPassordsSave() {
		insertJoe();
		UsernamePasswordAuthenticationToken currentAuth = UsernamePasswordAuthenticationToken.authenticated("joe", null,
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		Authentication updatedAuth = this.manager.createNewAuthentication(currentAuth, "new");
		assertThat(updatedAuth.getCredentials()).isNull();
	}

	private Authentication authenticateJoe() {
		UsernamePasswordAuthenticationToken auth = UsernamePasswordAuthenticationToken.authenticated("joe", "password",
				joe.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(auth);
		return auth;
	}

	private void insertJoe() {
		this.template.execute("insert into users (username, password, enabled) values ('joe','password','true')");
		this.template.execute("insert into authorities (username, authority) values ('joe','A')");
		this.template.execute("insert into authorities (username, authority) values ('joe','B')");
		this.template.execute("insert into authorities (username, authority) values ('joe','C')");
		this.cache.putUserInCache(joe);
	}

	private class MockUserCache implements UserCache {

		private Map<String, UserDetails> cache = new HashMap<>();

		@Override
		public UserDetails getUserFromCache(String username) {
			return this.cache.get(username);
		}

		@Override
		public void putUserInCache(UserDetails user) {
			this.cache.put(user.getUsername(), user);
		}

		@Override
		public void removeUserFromCache(String username) {
			this.cache.remove(username);
		}

		Map<String, UserDetails> getUserMap() {
			return this.cache;
		}

	}

}
