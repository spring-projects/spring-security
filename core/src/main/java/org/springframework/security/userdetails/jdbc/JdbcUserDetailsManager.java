package org.springframework.security.userdetails.jdbc;

import org.springframework.security.AccessDeniedException;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.dao.UserCache;
import org.springframework.security.providers.dao.cache.NullUserCache;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsManager;
import org.springframework.security.userdetails.GroupsManager;
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
public class JdbcUserDetailsManager extends JdbcDaoImpl implements UserDetailsManager, GroupsManager {
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

    // GroupsManager SQL
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

    private AuthenticationManager authenticationManager;

    private UserCache userCache = new NullUserCache();

    //~ Methods ========================================================================================================

    protected void initDao() throws ApplicationContextException {
        if (authenticationManager == null) {
            logger.info("No authentication manager set. Reauthentication of users when changing passwords will" +
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

        super.initDao();
    }

    //~ UserDetailsManager implementation ==============================================================================

    public void createUser(UserDetails user) {
        insertUser.update(new Object[] {user.getUsername(), user.getPassword(), Boolean.valueOf(user.isEnabled())});

        for (int i=0; i < user.getAuthorities().length; i++) {
            insertAuthority.update(user.getUsername(), user.getAuthorities()[i].getAuthority());
        }
    }

    public void updateUser(UserDetails user) {
        updateUser.update(new Object[] {user.getPassword(), Boolean.valueOf(user.isEnabled()), user.getUsername()});
        deleteUserAuthorities.update(user.getUsername());

        for (int i=0; i < user.getAuthorities().length; i++) {
            insertAuthority.update(user.getUsername(), user.getAuthorities()[i].getAuthority());
        }

        userCache.removeUserFromCache(user.getUsername());
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

    public List findAllGroups() {
        return findAllGroupsQuery.execute();
    }

    public List findUsersInGroup(String groupName) {
        Assert.hasText(groupName);
        return findUsersInGroupQuery.execute(groupName);
    }

    public void createGroup(String groupName, GrantedAuthority[] authorities) {
        Assert.hasText(groupName);
        Assert.notNull(authorities);

        insertGroup.update(groupName);
        Integer key = (Integer) findGroupIdQuery.findObject(groupName);

        for (int i=0; i < authorities.length; i++) {
            insertGroupAuthority.update( new Object[] {key, authorities[i].getAuthority()});
        }
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
}
