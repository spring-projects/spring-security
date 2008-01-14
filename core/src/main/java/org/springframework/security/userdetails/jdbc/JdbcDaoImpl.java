/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.userdetails.jdbc;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.SpringSecurityMessageSource;

import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.UsernameNotFoundException;

import org.springframework.context.ApplicationContextException;
import org.springframework.context.support.MessageSourceAccessor;

import org.springframework.dao.DataAccessException;

import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.jdbc.object.MappingSqlQuery;
import org.springframework.util.Assert;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;

import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;

import javax.sql.DataSource;


/**
 * Retrieves user details (username, password, enabled flag, and authorities) from a JDBC location.
 * <p>
 * A default database structure is assumed, (see {@link #DEF_USERS_BY_USERNAME_QUERY} and {@link
 * #DEF_AUTHORITIES_BY_USERNAME_QUERY}, which most users of this class will need to override, if using an existing
 * scheme. This may be done by setting the default query strings used. If this does not provide enough flexibility,
 * another strategy would be to subclass this class and override the {@link MappingSqlQuery} instances used, via the
 * {@link #initMappingSqlQueries()} extension point.
 * <p>
 * In order to minimise backward compatibility issues, this DAO does not recognise the expiration of user
 * accounts or the expiration of user credentials. However, it does recognise and honour the user enabled/disabled
 * column.
 * <p>
 * Support for group-based authorities can be enabled by setting the <tt>enableGroups</tt> property to <tt>true</tt>
 * (you may also then wish to set <tt>enableAuthorities</tt> to <tt>false</tt> to disable loading of authorities
 * directly). With this approach, authorities are allocated to groups and a user's authorities are determined based
 * on the groups they are a member of. The net result is the same (a UserDetails containing a set of
 * <tt>GrantedAuthority</tt>s is loaded), but the different persistence strategy may be more suitable for the
 * administration of some applications.
 *
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @author Luke Taylor
 * @version $Id$
 */
public class JdbcDaoImpl extends JdbcDaoSupport implements UserDetailsService {
    //~ Static fields/initializers =====================================================================================

    public static final String DEF_USERS_BY_USERNAME_QUERY =
            "SELECT username,password,enabled " +
            "FROM users " +
            "WHERE username = ?";
    public static final String DEF_AUTHORITIES_BY_USERNAME_QUERY =
            "SELECT username,authority " +
            "FROM authorities " +
            "WHERE username = ?";
    public static final String DEF_GROUP_AUTHORITIES_BY_USERNAME_QUERY =
            "SELECT g.id, g.group_name, ga.authority " +
            "FROM groups g, group_members gm, group_authorities ga " +
            "WHERE gm.username = ? " +
            "AND g.id = ga.group_id " +
            "AND g.id = gm.group_id";

    //~ Instance fields ================================================================================================

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    protected MappingSqlQuery authoritiesByUsernameMapping;
    protected MappingSqlQuery groupAuthoritiesByUsernameMapping;
    protected MappingSqlQuery usersByUsernameMapping;

    private String authoritiesByUsernameQuery;
    private String groupAuthoritiesByUsernameQuery;
    private String usersByUsernameQuery;
    private String rolePrefix = "";
    private boolean usernameBasedPrimaryKey = true;
    private boolean enableAuthorities = true;
    private boolean enableGroups;

    //~ Constructors ===================================================================================================

    public JdbcDaoImpl() {
        usersByUsernameQuery = DEF_USERS_BY_USERNAME_QUERY;
        authoritiesByUsernameQuery = DEF_AUTHORITIES_BY_USERNAME_QUERY;
        groupAuthoritiesByUsernameQuery = DEF_GROUP_AUTHORITIES_BY_USERNAME_QUERY;
    }

    //~ Methods ========================================================================================================

    /**
     * Allows subclasses to add their own granted authorities to the list to be returned in the
     * <code>User</code>.
     *
     * @param username the username, for use by finder methods
     * @param authorities the current granted authorities, as populated from the <code>authoritiesByUsername</code>
     *        mapping
     */
    protected void addCustomAuthorities(String username, List authorities) {}

    public String getUsersByUsernameQuery() {
        return usersByUsernameQuery;
    }

    protected void initDao() throws ApplicationContextException {
        Assert.isTrue(enableAuthorities || enableGroups, "Use of either authorities or groups must be enabled");
        initMappingSqlQueries();
    }

    /**
     * Extension point to allow other MappingSqlQuery objects to be substituted in a subclass
     */
    protected void initMappingSqlQueries() {
        this.usersByUsernameMapping = new UsersByUsernameMapping(getDataSource());
        this.authoritiesByUsernameMapping = new AuthoritiesByUsernameMapping(getDataSource());
        this.groupAuthoritiesByUsernameMapping = new GroupAuthoritiesByUsernameMapping(getDataSource());
    }

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        List users = usersByUsernameMapping.execute(username);

        if (users.size() == 0) {
            throw new UsernameNotFoundException(
                    messages.getMessage("JdbcDaoImpl.notFound", new Object[]{username}, "Username {0} not found"));
        }

        UserDetails user = (UserDetails) users.get(0); // contains no GrantedAuthority[]

        Set dbAuthsSet = new HashSet();

        if (enableAuthorities) {
            dbAuthsSet.addAll(authoritiesByUsernameMapping.execute(user.getUsername()));
        }

        if (enableGroups) {
            dbAuthsSet.addAll(groupAuthoritiesByUsernameMapping.execute(user.getUsername()));
        }

        List dbAuths = new ArrayList(dbAuthsSet);

        addCustomAuthorities(user.getUsername(), dbAuths);

        if (dbAuths.size() == 0) {
            throw new UsernameNotFoundException(
                    messages.getMessage("JdbcDaoImpl.noAuthority",
                            new Object[] {username}, "User {0} has no GrantedAuthority"));
        }

        GrantedAuthority[] arrayAuths = (GrantedAuthority[]) dbAuths.toArray(new GrantedAuthority[dbAuths.size()]);

        String returnUsername = user.getUsername();

        if (!usernameBasedPrimaryKey) {
            returnUsername = username;
        }

        return new User(returnUsername, user.getPassword(), user.isEnabled(), true, true, true, arrayAuths);
    }

    /**
     * Allows the default query string used to retrieve authorities based on username to be overriden, if
     * default table or column names need to be changed. The default query is {@link
     * #DEF_AUTHORITIES_BY_USERNAME_QUERY}; when modifying this query, ensure that all returned columns are mapped
     * back to the same column names as in the default query.
     *
     * @param queryString The query string to set
     */
    public void setAuthoritiesByUsernameQuery(String queryString) {
        authoritiesByUsernameQuery = queryString;
    }

    protected String getAuthoritiesByUsernameQuery() {
        return authoritiesByUsernameQuery;
    }

    /**
     * Allows the default query string used to retrieve group authorities based on username to be overriden, if
     * default table or column names need to be changed. The default query is {@link
     * #DEF_GROUP_AUTHORITIES_BY_USERNAME_QUERY}; when modifying this query, ensure that all returned columns are mapped
     * back to the same column names as in the default query.
     *
     * @param queryString The query string to set
     */
    public void setGroupAuthoritiesByUsernameQuery(String queryString) {
        groupAuthoritiesByUsernameQuery = queryString;
    }

    /**
     * Allows a default role prefix to be specified. If this is set to a non-empty value, then it is
     * automatically prepended to any roles read in from the db. This may for example be used to add the
     * <tt>ROLE_</tt> prefix expected to exist in role names (by default) by some other Spring Security
     * classes, in the case that the prefix is not already present in the db.
     *
     * @param rolePrefix the new prefix
     */
    public void setRolePrefix(String rolePrefix) {
        this.rolePrefix = rolePrefix;
    }

    protected String getRolePrefix() {
        return rolePrefix;
    }

    /**
     * If <code>true</code> (the default), indicates the {@link #getUsersByUsernameQuery()} returns a username
     * in response to a query. If <code>false</code>, indicates that a primary key is used instead. If set to
     * <code>true</code>, the class will use the database-derived username in the returned <code>UserDetails</code>.
     * If <code>false</code>, the class will use the {@link #loadUserByUsername(String)} derived username in the
     * returned <code>UserDetails</code>.
     *
     * @param usernameBasedPrimaryKey <code>true</code> if the mapping queries return the username <code>String</code>,
     *        or <code>false</code> if the mapping returns a database primary key.
     */
    public void setUsernameBasedPrimaryKey(boolean usernameBasedPrimaryKey) {
        this.usernameBasedPrimaryKey = usernameBasedPrimaryKey;
    }

    protected boolean isUsernameBasedPrimaryKey() {
        return usernameBasedPrimaryKey;
    }

    /**
     * Allows the default query string used to retrieve users based on username to be overriden, if default
     * table or column names need to be changed. The default query is {@link #DEF_USERS_BY_USERNAME_QUERY}; when
     * modifying this query, ensure that all returned columns are mapped back to the same column names as in the
     * default query. If the 'enabled' column does not exist in the source db, a permanent true value for this column
     * may be returned by using a query similar to <br><pre>
     * "SELECT username,password,'true' as enabled FROM users WHERE username = ?"</pre>
     *
     * @param usersByUsernameQueryString The query string to set
     */
    public void setUsersByUsernameQuery(String usersByUsernameQueryString) {
        this.usersByUsernameQuery = usersByUsernameQueryString;
    }

    protected boolean getEnableAuthorities() {
        return enableAuthorities;
    }

    /**
     * Enables loading of authorities (roles) from the authorities table. Defaults to true
     */
    public void setEnableAuthorities(boolean enableAuthorities) {
        this.enableAuthorities = enableAuthorities;
    }

    protected boolean getEnableGroups() {
        return enableGroups;
    }

    /**
     * Enables support for group authorities. Defaults to false
     * @param enableGroups
     */
    public void setEnableGroups(boolean enableGroups) {
        this.enableGroups = enableGroups;
    }

    //~ Inner Classes ==================================================================================================

    /**
     * Query object to look up a user's authorities.
     */
    protected class AuthoritiesByUsernameMapping extends MappingSqlQuery {
        protected AuthoritiesByUsernameMapping(DataSource ds) {
            super(ds, authoritiesByUsernameQuery);
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }

        protected Object mapRow(ResultSet rs, int rownum) throws SQLException {
            String roleName = rolePrefix + rs.getString(2);
            GrantedAuthorityImpl authority = new GrantedAuthorityImpl(roleName);

            return authority;
        }
    }

    protected class GroupAuthoritiesByUsernameMapping extends MappingSqlQuery {
        protected GroupAuthoritiesByUsernameMapping(DataSource ds) {
            super(ds, groupAuthoritiesByUsernameQuery);
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }

        protected Object mapRow(ResultSet rs, int rownum) throws SQLException {
            String roleName = rolePrefix + rs.getString(3);
            GrantedAuthorityImpl authority = new GrantedAuthorityImpl(roleName);

            return authority;
        }
    }

    /**
     * Query object to look up a user.
     */
    protected class UsersByUsernameMapping extends MappingSqlQuery {
        protected UsersByUsernameMapping(DataSource ds) {
            super(ds, usersByUsernameQuery);
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }

        protected Object mapRow(ResultSet rs, int rownum) throws SQLException {
            String username = rs.getString(1);
            String password = rs.getString(2);
            boolean enabled = rs.getBoolean(3);
            UserDetails user = new User(username, password, enabled, true, true, true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("HOLDER")});

            return user;
        }
    }
}
