/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.providers.dao.jdbc;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.providers.dao.AuthenticationDao;
import net.sf.acegisecurity.providers.dao.User;
import net.sf.acegisecurity.providers.dao.UsernameNotFoundException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContextException;

import org.springframework.dao.DataAccessException;

import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.jdbc.object.MappingSqlQuery;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;

import java.util.List;

import javax.sql.DataSource;


/**
 * Retrieves user details from a JDBC location provided by the bean context.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JdbcDaoImpl extends JdbcDaoSupport implements AuthenticationDao {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(JdbcDaoSupport.class);

    //~ Instance fields ========================================================

    private AuthoritiesByUsernameQuery authoritiesByUsernameQuery;
    private UsersByUsernameQuery usersByUsernameQuery;

    //~ Methods ================================================================

    public User loadUserByUsername(String username)
        throws UsernameNotFoundException, DataAccessException {
        List users = usersByUsernameQuery.execute(username);

        if (users.size() == 0) {
            throw new UsernameNotFoundException("User not found");
        }

        User user = (User) users.get(0); // contains no GrantedAuthority[]

        List dbAuths = authoritiesByUsernameQuery.execute(user.getUsername());

        if (dbAuths.size() == 0) {
            throw new UsernameNotFoundException("User has no GrantedAuthority");
        }

        GrantedAuthority[] arrayAuths = {new GrantedAuthorityImpl("demo")};
        arrayAuths = (GrantedAuthority[]) dbAuths.toArray(arrayAuths);

        return new User(user.getUsername(), user.getPassword(),
            user.isEnabled(), arrayAuths);
    }

    protected void setAuthoritiesByUsernameQuery(
        AuthoritiesByUsernameQuery authoritiesByUsernameQuery) {
        this.authoritiesByUsernameQuery = authoritiesByUsernameQuery;
    }

    protected void setUsersByUsernameQuery(
        UsersByUsernameQuery usersByUsernameQuery) {
        this.usersByUsernameQuery = usersByUsernameQuery;
    }

    protected void initDao() throws ApplicationContextException {
        if (usersByUsernameQuery == null) {
            usersByUsernameQuery = new UsersByUsernameQuery(getDataSource());
        }

        if (authoritiesByUsernameQuery == null) {
            authoritiesByUsernameQuery = new AuthoritiesByUsernameQuery(getDataSource());
        }
    }

    //~ Inner Classes ==========================================================

    /**
     * Query object to look up a user's authorities.
     */
    protected static class AuthoritiesByUsernameQuery extends MappingSqlQuery {
        protected AuthoritiesByUsernameQuery(DataSource ds) {
            super(ds,
                "SELECT username,authority FROM authorities WHERE username = ?");
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }

        protected Object mapRow(ResultSet rs, int rownum)
            throws SQLException {
            GrantedAuthorityImpl authority = new GrantedAuthorityImpl(rs
                    .getString("authority"));

            return authority;
        }
    }

    /**
     * Query object to look up a user.
     */
    protected static class UsersByUsernameQuery extends MappingSqlQuery {
        protected UsersByUsernameQuery(DataSource ds) {
            super(ds,
                "SELECT username,password,enabled FROM users WHERE username = ?");
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }

        protected Object mapRow(ResultSet rs, int rownum)
            throws SQLException {
            String username = rs.getString("username");
            String password = rs.getString("password");
            boolean enabled = rs.getBoolean("enabled");
            User user = new User(username, password, enabled, null);

            return user;
        }
    }
}
