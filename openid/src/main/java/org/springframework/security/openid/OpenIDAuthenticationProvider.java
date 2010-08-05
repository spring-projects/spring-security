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
package org.springframework.security.openid;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;


/**
 * Finalises the OpenID authentication by obtaining local authorities for the authenticated user.
 * <p>
 * The authorities are obtained by calling the configured <tt>UserDetailsService</tt>.
 * The <code>UserDetails</code> it returns must, at minimum, contain the username and <code>GrantedAuthority</code>
 * objects applicable to the authenticated user. Note that by default, Spring Security ignores the password and
 * enabled/disabled status of the <code>UserDetails</code> because this is
 * authentication-related and should have been enforced by another provider server.
 * <p>
 * The <code>UserDetails</code> returned by implementations is stored in the generated <code>AuthenticationToken</code>,
 * so additional properties such as email addresses, telephone numbers etc can easily be stored.
 *
 * @author Robin Bramley, Opsera Ltd.
 */
public class OpenIDAuthenticationProvider implements AuthenticationProvider, InitializingBean {
    //~ Instance fields ================================================================================================

    private AuthenticationUserDetailsService<OpenIDAuthenticationToken> userDetailsService;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.userDetailsService, "The userDetailsService must be set");
    }

    /* (non-Javadoc)
     * @see org.springframework.security.authentication.AuthenticationProvider#authenticate(org.springframework.security.Authentication)
     */
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {

        if (!supports(authentication.getClass())) {
            return null;
        }

        if (authentication instanceof OpenIDAuthenticationToken) {
            OpenIDAuthenticationToken response = (OpenIDAuthenticationToken) authentication;
            OpenIDAuthenticationStatus status = response.getStatus();

            // handle the various possibilities
            if (status == OpenIDAuthenticationStatus.SUCCESS) {
                // Lookup user details
                UserDetails userDetails = userDetailsService.loadUserDetails(response);

                return createSuccessfulAuthentication(userDetails, response);

            } else if (status == OpenIDAuthenticationStatus.CANCELLED) {
                throw new AuthenticationCancelledException("Log in cancelled");
            } else if (status == OpenIDAuthenticationStatus.ERROR) {
                throw new AuthenticationServiceException("Error message from server: " + response.getMessage());
            } else if (status == OpenIDAuthenticationStatus.FAILURE) {
                throw new BadCredentialsException("Log in failed - identity could not be verified");
            } else if (status == OpenIDAuthenticationStatus.SETUP_NEEDED) {
                throw new AuthenticationServiceException(
                        "The server responded setup was needed, which shouldn't happen");
            } else {
                throw new AuthenticationServiceException("Unrecognized return value " + status.toString());
            }
        }

        return null;
    }

    /**
     * Handles the creation of the final <tt>Authentication</tt> object which will be returned by the provider.
     * <p>
     * The default implementation just creates a new OpenIDAuthenticationToken from the original, but with the
     * UserDetails as the principal and including the authorities loaded by the UserDetailsService.
     *
     * @param userDetails the loaded UserDetails object
     * @param auth the token passed to the authenticate method, containing
     * @return the token which will represent the authenticated user.
     */
    protected Authentication createSuccessfulAuthentication(UserDetails userDetails, OpenIDAuthenticationToken auth) {
        return new OpenIDAuthenticationToken(userDetails, userDetails.getAuthorities(),
                auth.getIdentityUrl(), auth.getAttributes());
    }

    /**
     * Used to load the {@code UserDetails} for the authenticated OpenID user.
     */
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = new UserDetailsByNameServiceWrapper<OpenIDAuthenticationToken>(userDetailsService);
    }

    /**
     * Used to load the {@code UserDetails} for the authenticated OpenID user.
     */
    public void setAuthenticationUserDetailsService(AuthenticationUserDetailsService<OpenIDAuthenticationToken> userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.authentication.AuthenticationProvider#supports(java.lang.Class)
     */
    public boolean supports(Class<?> authentication) {
        return OpenIDAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
