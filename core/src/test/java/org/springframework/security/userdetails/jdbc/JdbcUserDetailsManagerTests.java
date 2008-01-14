package org.springframework.security.userdetails.jdbc;

import org.springframework.security.AccessDeniedException;
import org.springframework.security.Authentication;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.PopulatedDatabase;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.dao.UserCache;
import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.util.AuthorityUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.Collections;

/**
 * Tests for {@link JdbcUserDetailsManager}
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class JdbcUserDetailsManagerTests {
    private static final String SELECT_JOE_SQL = "select * from users where username = 'joe'";
    private static final String SELECT_JOE_AUTHORITIES_SQL = "select * from authorities where username = 'joe'";

    private static final UserDetails joe = new User("joe", "password", true, true, true, true,
            AuthorityUtils.stringArrayToAuthorityArray(new String[]{"A","C","B"}));

    private static DriverManagerDataSource dataSource;
    private JdbcUserDetailsManager manager;
    private MockUserCache cache;
    private JdbcTemplate template;

    @BeforeClass
    public static void createDataSource() {
        dataSource = new DriverManagerDataSource("org.hsqldb.jdbcDriver", "jdbc:hsqldb:mem:jdbcusermgrtest", "sa", "");
    }

    @AfterClass
    public static void clearDataSource() {
        dataSource = null;
    }

    @Before
    public void initializeManagerAndCreateTables() {
        manager = new JdbcUserDetailsManager();
        cache = new MockUserCache();
        manager.setUserCache(cache);
        manager.setDataSource(dataSource);
        manager.setCreateUserSql(JdbcUserDetailsManager.DEF_CREATE_USER_SQL);
        manager.setUpdateUserSql(JdbcUserDetailsManager.DEF_UPDATE_USER_SQL);
        manager.setUserExistsSql(JdbcUserDetailsManager.DEF_USER_EXISTS_SQL);
        manager.setCreateAuthoritySql(JdbcUserDetailsManager.DEF_INSERT_AUTHORITY_SQL);
        manager.setDeleteUserAuthoritiesSql(JdbcUserDetailsManager.DEF_DELETE_USER_AUTHORITIES_SQL);
        manager.setDeleteUserSql(JdbcUserDetailsManager.DEF_DELETE_USER_SQL);
        manager.setChangePasswordSql(JdbcUserDetailsManager.DEF_CHANGE_PASSWORD_SQL);
        manager.initDao();
        template = manager.getJdbcTemplate();

        template.execute("create table users(username varchar(20) not null primary key," +
                "password varchar(20) not null, enabled boolean not null)");
        template.execute("create table authorities (username varchar(20) not null, authority varchar(20) not null, " +
                "constraint fk_authorities_users foreign key(username) references users(username))");
        PopulatedDatabase.createGroupTables(template);
        PopulatedDatabase.insertGroupData(template);
    }

    @After
    public void dropTablesAndClearContext() {
        template.execute("drop table authorities");
        template.execute("drop table users");
        template.execute("drop table group_authorities");
        template.execute("drop table group_members");
        template.execute("drop table groups");
        SecurityContextHolder.clearContext();
    }

    @Test
    public void createUserInsertsCorrectData() {
        manager.createUser(joe);

        UserDetails joe2 = manager.loadUserByUsername("joe");

        assertEquals(joe, joe2);
    }

    @Test
    public void deleteUserRemovesUserDataAndAuthoritiesAndClearsCache() {
        insertJoe();
        manager.deleteUser("joe");

        assertEquals(0, template.queryForList(SELECT_JOE_SQL).size());
        assertEquals(0, template.queryForList(SELECT_JOE_AUTHORITIES_SQL).size());
        assertFalse(cache.getUserMap().containsKey("joe"));
    }

    @Test
    public void updateUserChangesDataCorrectlyAndClearsCache() {
        insertJoe();
        User newJoe = new User("joe","newpassword",false,true,true,true,
                AuthorityUtils.stringArrayToAuthorityArray(new String[]{"D","F","E"}));

        manager.updateUser(newJoe);

        UserDetails joe = manager.loadUserByUsername("joe");

        assertEquals(newJoe, joe);
        assertFalse(cache.getUserMap().containsKey("joe"));
    }

    @Test
    public void userExistsReturnsFalseForNonExistentUsername() {
        assertFalse(manager.userExists("joe"));
    }

    @Test
    public void userExistsReturnsTrueForExistingUsername() {
        insertJoe();
        assertTrue(manager.userExists("joe"));
        assertTrue(cache.getUserMap().containsKey("joe"));
    }

    @Test(expected = AccessDeniedException.class)
    public void changePasswordFailsForUnauthenticatedUser() {
        manager.changePassword("password", "newPassword");
    }

    @Test
    public void changePasswordSucceedsWithAuthenticatedUserAndNoAuthenticationManagerSet() {
        insertJoe();
        authenticateJoe();
        manager.changePassword("wrongpassword", "newPassword");
        UserDetails newJoe = manager.loadUserByUsername("joe");

        assertEquals("newPassword", newJoe.getPassword());
        assertFalse(cache.getUserMap().containsKey("joe"));
    }

    @Test
    public void changePasswordSucceedsWithIfReAuthenticationSucceeds() {
        insertJoe();
        Authentication currentAuth = authenticateJoe();
        manager.setAuthenticationManager(new MockAuthenticationManager(true));
        manager.changePassword("password", "newPassword");
        UserDetails newJoe = manager.loadUserByUsername("joe");

        assertEquals("newPassword", newJoe.getPassword());
        // The password in the context should also be altered
        Authentication newAuth = SecurityContextHolder.getContext().getAuthentication();
        assertEquals("joe", newAuth.getName());
        assertEquals(currentAuth.getDetails(), newAuth.getDetails());
        assertEquals("newPassword", newAuth.getCredentials());
        assertFalse(cache.getUserMap().containsKey("joe"));
    }

    @Test
    public void changePasswordFailsIfReAuthenticationFails() {
        insertJoe();
        authenticateJoe();
        manager.setAuthenticationManager(new MockAuthenticationManager(false));

        try {
            manager.changePassword("password", "newPassword");
            fail("Expected BadCredentialsException");
        } catch (BadCredentialsException expected) {
        }

        // Check password hasn't changed.
        UserDetails newJoe = manager.loadUserByUsername("joe");
        assertEquals("password", newJoe.getPassword());
        assertEquals("password", SecurityContextHolder.getContext().getAuthentication().getCredentials());
        assertTrue(cache.getUserMap().containsKey("joe"));
    }

    @Test
    public void findAllGroupsReturnsExpectedGroupNames() {
        List<String> groups = manager.findAllGroups();
        assertEquals(4, groups.size());

        Collections.sort(groups);
        assertEquals("GROUP_0", groups.get(0));
        assertEquals("GROUP_1", groups.get(1));
        assertEquals("GROUP_2", groups.get(2));
        assertEquals("GROUP_3", groups.get(3));
    }

    @Test
    public void findGroupMembersReturnsCorrectData() {
        List<String> groupMembers = manager.findUsersInGroup("GROUP_0");
        assertEquals(1, groupMembers.size());
        assertEquals("jerry", groupMembers.get(0));
        groupMembers = manager.findUsersInGroup("GROUP_1");
        assertEquals(2, groupMembers.size());
    }

    @Test
    public void createGroupInsertsCorrectData() {
        manager.createGroup("TEST_GROUP", AuthorityUtils.stringArrayToAuthorityArray(new String[] {"ROLE_X", "ROLE_Y"}));

        List roles = template.queryForList(
                "select ga.authority from groups g, group_authorities ga " +
                "where ga.group_id = g.id " +
                "and g.group_name = 'TEST_GROUP'");

        assertEquals(2, roles.size());
    }

    @Test
    public void deleteGroupRemovesData() throws Exception {
        manager.deleteGroup("GROUP_0");
        manager.deleteGroup("GROUP_1");
        manager.deleteGroup("GROUP_2");
        manager.deleteGroup("GROUP_3");

        assertEquals(0, template.queryForList("select * from group_authorities").size());
        assertEquals(0, template.queryForList("select * from group_members").size());
        assertEquals(0, template.queryForList("select id from groups").size());        
    }

    @Test
    public void renameGroupIsSuccessful() throws Exception {
        manager.renameGroup("GROUP_0", "GROUP_X");

        assertEquals(0, template.queryForInt("select id from groups where group_name = 'GROUP_X'"));
    }

    @Test
    public void addingGroupUserSetsCorrectData() throws Exception {
        manager.addUserToGroup("tom", "GROUP_0");

        assertEquals(2, template.queryForList("select username from group_members where group_id = 0").size());
    }

    private Authentication authenticateJoe() {
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken("joe","password", joe.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(auth);

        return auth;
    }

    private void insertJoe() {
        template.execute("insert into users (username, password, enabled) values ('joe','password','true')");
        template.execute("insert into authorities (username, authority) values ('joe','A')");
        template.execute("insert into authorities (username, authority) values ('joe','B')");
        template.execute("insert into authorities (username, authority) values ('joe','C')");
        cache.putUserInCache(joe);
    }

    private class MockUserCache implements UserCache {
        private Map cache = new HashMap();

        public UserDetails getUserFromCache(String username) {
            return (User) cache.get(username);
        }

        public void putUserInCache(UserDetails user) {
            cache.put(user.getUsername(), user);
        }

        public void removeUserFromCache(String username) {
            cache.remove(username);
        }

        Map getUserMap() {
            return cache;
        }
    }
}
