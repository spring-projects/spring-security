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
package org.springframework.security.userdetails.preauth;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataAccessException;
import org.springframework.security.Authentication;
import org.springframework.security.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * This implementation for AuthenticationUserDetailsService wraps a regular Spring Security
 * UserDetailsService implementation, to retrieve a UserDetails object based on the mapping of the
 * user name contained in a PreAuthenticatedAuthenticationToken to user name expected by the
 * userDetailsService.
 * 
 * @author Valery Tydykov
 */
public class UserDetailsMappingServiceWrapper implements AuthenticationUserDetailsService,
        InitializingBean {
    private UserDetailsService userDetailsService;

    private AccountMapper accountMapper;

    /**
     * Check whether all required properties have been set.
     * 
     * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
     */
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.userDetailsService, "UserDetailsService must be set");
        Assert.notNull(this.accountMapper, "AccountMapper must be set");
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.springframework.security.userdetails.AuthenticationUserDetailsService#loadUserDetails(org.springframework.security.Authentication)
     */
    public UserDetails loadUserDetails(Authentication authentication)
            throws UsernameNotFoundException, DataAccessException {

        // Determine username for the secondary authentication repository
        String username = this.getAccountMapper().map(authentication);

        // get the UserDetails object from the wrapped UserDetailsService implementation
        return userDetailsService.loadUserByUsername(username);
    }

    /**
     * Set the wrapped UserDetailsService implementation
     * 
     * @param aUserDetailsService The wrapped UserDetailsService to set
     */
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        Assert.notNull(userDetailsService, "UserDetailsService must not be null");
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
        Assert.notNull(accountMapper, "accountMapper must not be null");
        this.accountMapper = accountMapper;
    }

    /**
     * @return the userDetailsService
     */
    public UserDetailsService getUserDetailsService() {
        return this.userDetailsService;
    }
}
