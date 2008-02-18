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

package org.springframework.security.providers.siteminder;

import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationServiceException;
import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.UserDetailsChecker;
import org.springframework.security.userdetails.checker.AccountStatusUserDetailsChecker;

import org.springframework.dao.DataAccessException;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation that retrieves user details from an {@link UserDetailsService}.
 *
 * @author Scott McCrory
 * @version $Id$
 */
public class SiteminderAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {
    
    //~ Instance fields ================================================================================================

    /**
     * Our user details service (which does the real work of checking the user against a back-end user store).
     */
    private UserDetailsService userDetailsService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    //~ Methods ========================================================================================================

    /**
     * @see org.springframework.security.providers.dao.AbstractUserDetailsAuthenticationProvider#additionalAuthenticationChecks(org.springframework.security.userdetails.UserDetails, org.springframework.security.providers.UsernamePasswordAuthenticationToken)
     */
    protected void additionalAuthenticationChecks(final UserDetails user,
            final UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

        // No need for password authentication checks - we only expect one identifying string
        // from the HTTP Request header (as populated by Siteminder), but we do need to see if
        // the user's account is OK to let them in.

        userDetailsChecker.check(user);
    }

    /**
     * @see org.springframework.security.providers.dao.AbstractUserDetailsAuthenticationProvider#doAfterPropertiesSet()
     */
    protected void doAfterPropertiesSet() throws Exception {
        Assert.notNull(this.userDetailsService, "A UserDetailsService must be set");
    }

    /**
     * Return the user details service.
     * @return The user details service.
     */
    public UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    /**
     * @see org.springframework.security.providers.dao.AbstractUserDetailsAuthenticationProvider#retrieveUser(java.lang.String, org.springframework.security.providers.UsernamePasswordAuthenticationToken)
     */
    protected final UserDetails retrieveUser(final String username,
            final UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

        UserDetails loadedUser;

        try {
            loadedUser = this.getUserDetailsService().loadUserByUsername(username);
        } catch (DataAccessException repositoryProblem) {
            throw new AuthenticationServiceException(repositoryProblem.getMessage(), repositoryProblem);
        }

        if (loadedUser == null) {
            throw new AuthenticationServiceException(
                    "UserDetailsService returned null, which is an interface contract violation");
        }

        return loadedUser;
    }

    /**
     * Sets the user details service.
     * @param userDetailsService The user details service.
     */
    public void setUserDetailsService(final UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

}
