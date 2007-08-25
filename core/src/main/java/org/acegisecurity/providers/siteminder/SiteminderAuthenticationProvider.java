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

package org.acegisecurity.providers.siteminder;

import org.acegisecurity.AccountExpiredException;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.CredentialsExpiredException;
import org.acegisecurity.DisabledException;
import org.acegisecurity.LockedException;
import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation that retrieves user details from an {@link UserDetailsService}.
 *
 * @author Scott McCrory
 * @version $Id: SiteminderAuthenticationProvider.java 1582 2006-07-15 15:18:51Z smccrory $
 */
public class SiteminderAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {
	

    /**
     * Our logging object
     */
    private static final Log logger = LogFactory.getLog(SiteminderAuthenticationProvider.class);

    //~ Instance fields ================================================================================================

    /**
     * Our user details service (which does the real work of checking the user against a back-end user store).
     */
    private UserDetailsService userDetailsService;
    
    //~ Methods ========================================================================================================

    /**
     * @see org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider#additionalAuthenticationChecks(org.acegisecurity.userdetails.UserDetails, org.acegisecurity.providers.UsernamePasswordAuthenticationToken)
     */
    protected void additionalAuthenticationChecks(final UserDetails user,
            final UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

        // No need for password authentication checks - we only expect one identifying string
        // from the HTTP Request header (as populated by Siteminder), but we do need to see if
        // the user's account is OK to let them in.
        if (!user.isEnabled()) {
            throw new DisabledException(messages.getMessage("AbstractUserDetailsAuthenticationProvider.disabled",
                    "Account disabled"));
        }

        if (!user.isAccountNonExpired()) {
            throw new AccountExpiredException(messages.getMessage("AbstractUserDetailsAuthenticationProvider.expired",
                    "Account expired"));
        }

        if (!user.isAccountNonLocked()) {
            throw new LockedException(messages.getMessage("AbstractUserDetailsAuthenticationProvider.locked",
                    "Account locked"));
        }

        if (!user.isCredentialsNonExpired()) {
            throw new CredentialsExpiredException(messages.getMessage(
                    "AbstractUserDetailsAuthenticationProvider.credentialsExpired", "Credentials expired"));
        }

    }

    /**
     * @see org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider#doAfterPropertiesSet()
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
     * @see org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider#retrieveUser(java.lang.String, org.acegisecurity.providers.UsernamePasswordAuthenticationToken)
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
