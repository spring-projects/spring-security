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
package org.springframework.security.userdetails.ldap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataAccessException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationServiceException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.util.Assert;

import java.util.List;
/**
 * The context mapper used by the LDAP authentication provider to create an LDAP user object.
 * Creates the final <tt>UserDetails</tt> object that will be returned by the provider once the
 * user has been authenticated, replacing the original <tt>UserDetails</tt> object. Has additional
 * properties <tt>userDetailsService</tt> and <tt>accountMapper</tt>, which are used to map
 * original user to username in secondary repository and to retrieve UserDetails from the secondary
 * account repository.
 * 
 * 
 * @author Valery Tydykov
 * 
 */
public class ReplacingUserDetailsMapper extends LdapUserDetailsMapper implements InitializingBean {

    /**
     * Logger for this class and subclasses
     */
    protected final Log logger = LogFactory.getLog(this.getClass());

    /**
     * service which will be used to retrieve UserDetails from the secondary account repository
     */
    private UserDetailsService userDetailsService;

    /**
     * mapper which will be used to map original user to username in secondary repository
     */
    private AccountMapper accountMapper;

    /**
     * @return the userDetailsService
     */
    public UserDetailsService getUserDetailsService() {
        return this.userDetailsService;
    }

    /**
     * @param userDetailsService the userDetailsService to set
     */
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        Assert.notNull(userDetailsService, "UserDetailsService must be supplied");
        this.userDetailsService = userDetailsService;
    }

    /**
     * @return the accountMapper
     */
    public AccountMapper getAccountMapper() {
        return this.accountMapper;
    }

    /**
     * @param accountMapper the accountMapper to set
     */
    public void setAccountMapper(AccountMapper accountMapper) {
        Assert.notNull(accountMapper, "AccountMapper must be supplied");
        this.accountMapper = accountMapper;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(userDetailsService, "UserDetailsService must be supplied");
        Assert.notNull(accountMapper, "AccountMapper must be supplied");
    }

    /*
     * Creates the final <tt>UserDetails</tt> object that will be returned by the provider once
     * the user has been authenticated, replacing the original <tt>UserDetails</tt> object.
     */
    public UserDetails mapUserFromContext(DirContextOperations ctx, String username,
            List<GrantedAuthority> authorities) {
        UserDetails userOriginal = super.mapUserFromContext(ctx, username, authorities);

        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Replacing UserDetails with username=[" + userOriginal.getUsername()
                    + "]");
        }

        // map user to secondary username
        String usernameMapped = this.getAccountMapper().map(userOriginal);

        // replace original UserDetails with the secondary UserDetails
        UserDetails user = retrieveUser(usernameMapped);

        return user;
    }

    protected UserDetails retrieveUser(String username) throws AuthenticationException {
        UserDetails loadedUser;

        // retrieve UserDetails from the secondary account repository
        try {
            loadedUser = this.getUserDetailsService().loadUserByUsername(username);
        } catch (DataAccessException repositoryProblem) {
            throw new AuthenticationServiceException(repositoryProblem.getMessage(),
                repositoryProblem);
        }

        if (loadedUser == null) {
            throw new AuthenticationServiceException(
                "UserDetailsService returned null, which is an interface contract violation");
        }

        return loadedUser;
    }
}
