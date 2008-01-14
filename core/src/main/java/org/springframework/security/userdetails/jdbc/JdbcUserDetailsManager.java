package org.springframework.security.userdetails.jdbc;

import org.springframework.security.AccessDeniedException;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.util.AuthorityUtils;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.dao.UserCache;
import org.springframework.security.providers.dao.cache.NullUserCache;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsManager;
import org.springframework.security.userdetails.GroupManager;
import org.springframework.context.ApplicationContextException;
import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.object.MappingSqlQuery;
import org.springframework.jdbc.object.SqlQuery;
import org.springframework.jdbc.object.SqlUpdate;
import org.springframework.util.Assert;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;

/**
 * Jdbc user management service.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class JdbcUserDetailsManager extends JdbcDaoImpl implements UserDetailsManager, GroupManager {
    //~ Static fields/initializers =====================================================================================

    // UserDetailsManager SQL
    public static final String DEF_CREATE_USER_SQL =
            "insert into users (username, password, enabled) values (?,?,?)";
    public static final String DEF_DELETE_USER_SQL =
            "delete from users where username = ?";
    public static final String DEF_UPDATE_USER_SQL =
            "update users set password = ?, enabled = ? where username = ?";
    public static final String DEF_INSERT_AUTHORITY_SQL =
            "insert into authorities (username, authority) values (?,?)";
    public static final String DEF_DELETE_USER_AUTHORITIES_SQL =
            "delete from authorities where username = ?";
    public static final String DEF_USER_EXISTS_SQL =
            "select username from users where username = ?";
    public static final String DEF_CHANGE_PASSWORD_SQL =
            "update users set password = ? where username = ?";

    // GroupManager SQL
    public static final String DEF_FIND_GROUPS_SQL =
            "select group_name from groups";
    public static final String DEF_FIND_USERS_IN_GROUP_SQL =
            "select username from group_members gm, groups g " +
            "where gm.group_id = g.id" +
            " and g.group_name = ?";
    public static final String DEF_INSERT_GROUP_SQL =
            "insert into groups (group_name) values (?)";
    public static final String DEF_FIND_GROUP_ID_SQL =
            "select id from groups where group_name = ?";
    public static final String DEF_INSERT_GROUP_AUTHORITY_SQL =
            "insert into group_authorities (group_id, authority) values (?,?)";
    public static final String DEF_DELETE_GROUP_SQL =
            "delete from groups where id = ?";
    public static final String DEF_DELETE_GROUP_AUTHORITIES_SQL =
            "delete from group_authorities where group_id = ?";
    public static final String DEF_DELETE_GROUP_MEMBERS_SQL =
            "delete from group_members where group_id = ?";
    public static final String DEF_RENAME_GROUP_SQL =
            "update groups set group_name = ? where group_name = ?";
    public static final String DEF_INSERT_GROUP_MEMBER_SQL =
            "insert into group_members (group_id, username) values (?,?)";
    public static final String DEF_DELETE_GROUP_MEMBER_SQL =
            "delete from group_members where group_id = ? and username = ?";
    public static final String DEF_GROUP_AUTHORITIES_QUERY_SQL =
            "select g.id, g.group_name, ga.authority " +
            "from groups g, group_authorities ga " +
            "where g.group_name = ? " +
            "and g.id = ga.group_id ";
    public static final String DEF_DELETE_GROUP_AUTHORITY_SQL =
            "delete from group_authorities where group_id = ? and authority = ?";


    //~ Instance fields ================================================================================================

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

    protected SqlUpdate insertUser;
    protected SqlUpdate deleteUser;
    protected SqlUpdate updateUser;
    protected SqlUpdate insertAuthority;
    protected SqlUpdate deleteUserAuthorities;
    protected SqlQuery  userExistsQuery;
    protected SqlUpdate changePassword;

    protected SqlQuery  findAllGroupsQuery;
    protected SqlQuery  findUsersInGroupQuery;
    protected SqlUpdate insertGroup;
    protected SqlQuery  findGroupIdQuery;
    protected SqlUpdate insertGroupAuthority;
    protected SqlUpdate deleteGroup;
    protected SqlUpdate deleteGroupMembers;
    protected SqlUpdate deleteGroupAuthorities;
    protected SqlUpdate renameGroup;
    protected SqlUpdate insertGroupMember;
    protected SqlUpdate deleteGroupMember;
    protected SqlQuery groupAuthoritiesQuery;
    protected SqlUpdate deleteGroupAuthority;

    private AuthenticationManager authenticationManager;

    private UserCache userCache = new NullUserCache();

    //~ Methods ========================================================================================================

    protected void initDao() throws ApplicationContextException {
        if (authenticationManager == null) {
            logger.info("No authentication manager set. Reauthentication of users when changing passwords will " +
                    "not be performed.");
        }

        insertUser = new InsertUser(getDataSource());
        deleteUser = new DeleteUser(getDataSource());
        updateUser = new UpdateUser(getDataSource());
        insertAuthority = new InsertAuthority(getDataSource());
        deleteUserAuthorities = new DeleteUserAuthorities(getDataSource());
        userExistsQuery = new UserExistsQuery(getDataSource());
        changePassword = new ChangePassword(getDataSource());

        findAllGroupsQuery = new AllGroupsQuery(getDataSource());
        findUsersInGroupQuery = new GroupMembersQuery(getDataSource());
        insertGroup = new InsertGroup(getDataSource());
        findGroupIdQuery = new FindGroupIdQuery(getDataSource());
        insertGroupAuthority = new InsertGroupAuthority(getDataSource());
        deleteGroup = new DeleteGroup(getDataSource());
        deleteGroupAuthorities = new DeleteGroupAuthorities(getDataSource());
        deleteGroupMembers = new DeleteGroupMembers(getDataSource());
        renameGroup = new RenameGroup(getDataSource());
        insertGroupMember = new InsertGroupMember(getDataSource());
        deleteGroupMember = new DeleteGroupMember (getDataSource());
        groupAuthoritiesQuery = new GroupAuthoritiesByGroupNameMapping(getDataSource());
        deleteGroupAuthority = new DeleteGroupAuthority(getDataSource());

        super.initDao();
    }

    //~ UserDetailsManager implementation ==============================================================================

    public void createUser(UserDetails user) {
        validateUserDetails(user);
        insertUser.update(new Object[] {user.getUsername(), user.getPassword(), Boolean.valueOf(user.isEnabled())});
        insertUserAuthorities(user);
    }

    public void updateUser(UserDetails user) {
        validateUserDetails(user);
        updateUser.update(new Object[] {user.getPassword(), Boolean.valueOf(user.isEnabled()), user.getUsername()});
        deleteUserAuthorities.update(user.getUsername());
        insertUserAuthorities(user);

        userCache.removeUserFromCache(user.getUsername());
    }

    private void insertUserAuthorities(UserDetails user) {
        for (int i=0; i < user.getAuthorities().length; i++) {
            insertAuthority.update(user.getUsername(), user.getAuthorities()[i].getAuthority());
        }
    }

    public void deleteUser(String username) {
        deleteUserAuthorities.update(username);
        deleteUser.update(username);
        userCache.removeUserFromCache(username);
    }

    public void changePassword(String oldPassword, String newPassword) throws AuthenticationException {
        Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();

        if (currentUser == null) {
            // This would indicate bad coding somewhere
            throw new AccessDeniedException("Can't change password as no Authentication object found in context " +
                    "for current user.");
        }

        String username = currentUser.getName();

        // If an authentication manager has been set, reauthenticate the user with the supplied password.
        if (authenticationManager != null) {
            logger.debug("Reauthenticating user '"+ username + "' for password change request.");

            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, oldPassword));
        } else {
            logger.debug("No authentication manager set. Password won't be re-checked.");
        }

        logger.debug("Changing password for user '"+ username + "'");

        changePassword.update(new String[] {newPassword, username});

        SecurityContextHolder.getContext().setAuthentication(createNewAuthentication(currentUser, newPassword));

        userCache.removeUserFromCache(username);
    }

    protected Authentication createNewAuthentication(Authentication currentAuth, String newPassword) {
        UserDetails user = loadUserByUsername(currentAuth.getName());

        UsernamePasswordAuthenticationToken newAuthentication =
                new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
        newAuthentication.setDetails(currentAuth.getDetails());

        return newAuthentication;
    }

    public boolean userExists(String username) {
        List users = userExistsQuery.execute(username);

        if (users.size() > 1) {
            throw new IllegalStateException("More than one user found with name '" + username + "'");
        }

        return users.size() == 1;
    }

    //~ GroupManager implementation ====================================================================================

    public String[] findAllGroups() {
        return (String[]) findAllGroupsQuery.execute().toArray(new String[0]);
    }

    public String[] findUsersInGroup(String groupName) {
        Assert.hasText(groupName);
        return (String[]) findUsersInGroupQuery.execute(groupName).toArray(new String[0]);
    }

    public void createGroup(String groupName, GrantedAuthority[] authorities) {
        Assert.hasText(groupName);
        Assert.notNull(authorities);

        logger.debug("Creating new group '" + groupName + "' with authorities " +
                    AuthorityUtils.authorityArrayToSet(authorities));

        insertGroup.update(groupName);
        Integer id = (Integer) findGroupIdQuery.findObject(groupName);

        for (int i=0; i < authorities.length; i++) {
            insertGroupAuthority.update( new Object[] {id, authorities[i].getAuthority()});
        }
    }

    public void deleteGroup(String groupName) {
        logger.debug("Deleting group '" + groupName + "'");
        Assert.hasText(groupName);

        int id = ((Integer) findGroupIdQuery.findObject(groupName)).intValue();
        deleteGroupMembers.update(id);
        deleteGroupAuthorities.update(id);
        deleteGroup.update(id);
    }

    public void renameGroup(String oldName, String newName) {
        logger.debug("Changing group name from '" + oldName + "' to '" + newName + "'");
        Assert.hasText(oldName);
        Assert.hasText(newName);

        renameGroup.update(newName, oldName);
    }

    public void addUserToGroup(String username, String groupName) {
        logger.debug("Adding user '" + username + "' to group '" + groupName + "'");
        Assert.hasText(username);
        Assert.hasText(groupName);

        Integer id = (Integer) findGroupIdQuery.findObject(groupName);

        insertGroupMember.update(new Object[] {id, username});
        userCache.removeUserFromCache(username);
    }

    public void removeUserFromGroup(String username, String groupName) {
        logger.debug("Removing user '" + username + "' to group '" + groupName + "'");
        Assert.hasText(username);
        Assert.hasText(groupName);

        Integer id = (Integer) findGroupIdQuery.findObject(groupName);

        deleteGroupMember.update(new Object[] {id, username});
        userCache.removeUserFromCache(username);
    }

    public GrantedAuthority[] findGroupAuthorities(String groupName) {
        logger.debug("Loading authorities for group '" + groupName + "'");
        Assert.hasText(groupName);

        return (GrantedAuthority[]) groupAuthoritiesQuery.execute(groupName).toArray(new GrantedAuthority[0]);
    }

    public void removeGroupAuthority(String groupName, GrantedAuthority authority) {
        logger.debug("Removing authority '" + authority + "' from group '" + groupName + "'");
        Assert.hasText(groupName);
        Assert.notNull(authority);

        Integer id = (Integer) findGroupIdQuery.findObject(groupName);
        deleteGroupAuthority.update(new Object[] {id, authority});
    }

    public void addGroupAuthority(String groupName, GrantedAuthority authority) {
        logger.debug("Adding authority '" + authority + "' to group '" + groupName + "'");
        Assert.hasText(groupName);
        Assert.notNull(authority);

        Integer id = (Integer) findGroupIdQuery.findObject(groupName);
        insertGroupAuthority.update(new Object[] {id, authority.getAuthority()});
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public void setCreateUserSql(String createUserSql) {
        Assert.hasText(createUserSql);
        this.createUserSql = createUserSql;
    }

    public void setDeleteUserSql(String deleteUserSql) {
        Assert.hasText(deleteUserSql);
        this.deleteUserSql = deleteUserSql;
    }

    public void setUpdateUserSql(String updateUserSql) {
        Assert.hasText(updateUserSql);
        this.updateUserSql = updateUserSql;
    }

    public void setCreateAuthoritySql(String createAuthoritySql) {
        Assert.hasText(createAuthoritySql);
        this.createAuthoritySql = createAuthoritySql;
    }

    public void setDeleteUserAuthoritiesSql(String deleteUserAuthoritiesSql) {
        Assert.hasText(deleteUserAuthoritiesSql);
        this.deleteUserAuthoritiesSql = deleteUserAuthoritiesSql;
    }

    public void setUserExistsSql(String userExistsSql) {
        Assert.hasText(userExistsSql);
        this.userExistsSql = userExistsSql;
    }

    public void setChangePasswordSql(String changePasswordSql) {
        Assert.hasText(changePasswordSql);
        this.changePasswordSql = changePasswordSql;
    }

    public void setFindAllGroupsSql(String findAllGroupsSql) {
        this.findAllGroupsSql = findAllGroupsSql;
    }

    /**
     * Optionally sets the UserCache if one is in use in the application.
     * This allows the user to be removed from the cache after updates have taken place to avoid stale data.
     *
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

    private void validateAuthorities(GrantedAuthority[] authorities) {
        Assert.notNull(authorities, "Authorities list must not be null");

        for (int i=0; i < authorities.length; i++) {
            Assert.notNull(authorities[i], "Authorities list contains a null entry");
            Assert.hasText(authorities[i].getAuthority(), "getAuthority() method must return a non-empty string");
        }
    }

    //~ Inner Classes ==================================================================================================

    protected class InsertUser extends SqlUpdate {

        public InsertUser(DataSource ds) {
            super(ds, createUserSql);
            declareParameter(new SqlParameter(Types.VARCHAR));
            declareParameter(new SqlParameter(Types.VARCHAR));
            declareParameter(new SqlParameter(Types.BOOLEAN));
            compile();
        }
    }

    protected class DeleteUser extends SqlUpdate {
        public DeleteUser(DataSource ds) {
            super(ds, deleteUserSql);
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }
    }

    protected class InsertAuthority extends SqlUpdate {
        public InsertAuthority(DataSource ds) {
            super(ds, createAuthoritySql);
            declareParameter(new SqlParameter(Types.VARCHAR));
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }
    }

    protected class DeleteUserAuthorities extends SqlUpdate {
        public DeleteUserAuthorities(DataSource ds) {
            super(ds, deleteUserAuthoritiesSql);
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }
    }

    protected class UpdateUser extends SqlUpdate {
        public UpdateUser(DataSource ds) {
            super(ds, updateUserSql);
            declareParameter(new SqlParameter(Types.VARCHAR));
            declareParameter(new SqlParameter(Types.BOOLEAN));
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }
    }

    protected class ChangePassword extends SqlUpdate {
        public ChangePassword(DataSource ds) {
            super(ds, changePasswordSql);
            declareParameter(new SqlParameter(Types.VARCHAR));
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }
    }


    protected class UserExistsQuery extends MappingSqlQuery {
        public UserExistsQuery(DataSource ds) {
            super(ds, userExistsSql);
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }

        protected Object mapRow(ResultSet rs, int rowNum) throws SQLException {
            return rs.getString(1);
        }
    }

    protected class AllGroupsQuery extends MappingSqlQuery {
        public AllGroupsQuery(DataSource ds) {
            super(ds, findAllGroupsSql);
            compile();
        }

        protected Object mapRow(ResultSet rs, int rowNum) throws SQLException {
            return rs.getString(1);
        }
    }

    protected class GroupMembersQuery extends MappingSqlQuery {
        public GroupMembersQuery(DataSource ds) {
            super(ds, findUsersInGroupSql);
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }

        protected Object mapRow(ResultSet rs, int rowNum) throws SQLException {
            return rs.getString(1);
        }
    }

    protected class InsertGroup extends SqlUpdate {
        public InsertGroup(DataSource ds) {
            super(ds, insertGroupSql);
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }
    }

    private class FindGroupIdQuery extends MappingSqlQuery {
        public FindGroupIdQuery(DataSource ds) {
            super(ds, findGroupIdSql);
            declareParameter(new SqlParameter(Types.INTEGER));
            compile();
        }

        protected Object mapRow(ResultSet rs, int rowNum) throws SQLException {
            return Integer.valueOf(rs.getInt(1));
        }
    }

    protected class InsertGroupAuthority extends SqlUpdate {
        public InsertGroupAuthority(DataSource ds) {
            super(ds, insertGroupAuthoritySql);
            declareParameter(new SqlParameter(Types.INTEGER));
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }
    }

    protected class DeleteGroup extends SqlUpdate {
        public DeleteGroup(DataSource ds) {
            super(ds, deleteGroupSql);
            declareParameter(new SqlParameter(Types.INTEGER));
            compile();
        }
    }

    protected class DeleteGroupMembers extends SqlUpdate {
        public DeleteGroupMembers(DataSource ds) {
            super(ds, deleteGroupMembersSql);
            declareParameter(new SqlParameter(Types.INTEGER));
            compile();
        }
    }

    protected class DeleteGroupAuthorities extends SqlUpdate {
        public DeleteGroupAuthorities(DataSource ds) {
            super(ds, deleteGroupAuthoritiesSql);
            declareParameter(new SqlParameter(Types.INTEGER));
            compile();
        }
    }

    protected class RenameGroup extends SqlUpdate {
        public RenameGroup(DataSource ds) {
            super(ds, renameGroupSql);
            declareParameter(new SqlParameter(Types.VARCHAR));
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }
    }

    protected class InsertGroupMember extends SqlUpdate {
        public InsertGroupMember(DataSource ds) {
            super(ds, insertGroupMemberSql);
            declareParameter(new SqlParameter(Types.INTEGER));
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }
    }

    private class DeleteGroupMember extends SqlUpdate {
        public DeleteGroupMember(DataSource ds) {
            super(ds, deleteGroupMemberSql);
            declareParameter(new SqlParameter(Types.INTEGER));
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }
    }

    protected class GroupAuthoritiesByGroupNameMapping extends MappingSqlQuery {
         protected GroupAuthoritiesByGroupNameMapping(DataSource ds) {
             super(ds, groupAuthoritiesSql);
             declareParameter(new SqlParameter(Types.VARCHAR));
             compile();
         }

         protected Object mapRow(ResultSet rs, int rownum) throws SQLException {
             String roleName = getRolePrefix() + rs.getString(3);
             GrantedAuthorityImpl authority = new GrantedAuthorityImpl(roleName);

             return authority;
         }
    }

    private class DeleteGroupAuthority extends SqlUpdate {
        public DeleteGroupAuthority(DataSource ds) {
            super(ds, deleteGroupAuthoritySql);
            declareParameter(new SqlParameter(Types.INTEGER));
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }
    }
}
