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
package org.springframework.security.providers.openid;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationServiceException;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.security.providers.AuthoritiesPopulator;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.util.Assert;


/**
 * Finalises the OpenID authentication by obtaining local roles
 *
 * @author Robin Bramley, Opsera Ltd.
 */
public class OpenIDAuthenticationProvider implements AuthenticationProvider, InitializingBean {
    //~ Instance fields ================================================================================================

    private AuthoritiesPopulator authoritiesPopulator;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.authoritiesPopulator, "The authoritiesPopulator must be set");
    }

    /* (non-Javadoc)
     * @see org.springframework.security.providers.AuthenticationProvider#authenticate(org.springframework.security.Authentication)
     */
    public Authentication authenticate(final Authentication authentication)
            throws AuthenticationException {

        if (!supports(authentication.getClass())) {
            return null;
        }

        if (authentication instanceof OpenIDAuthenticationToken) {
            OpenIDAuthenticationToken response = (OpenIDAuthenticationToken) authentication;
            OpenIDAuthenticationStatus status = response.getStatus();

            // handle the various possibilites
            if (status == OpenIDAuthenticationStatus.SUCCESS) {

                // Lookup user details
                UserDetails userDetails = this.authoritiesPopulator.getUserDetails(response.getIdentityUrl());

                return new OpenIDAuthenticationToken(userDetails.getAuthorities(), response.getStatus(),
                        response.getIdentityUrl());

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

    public void setAuthoritiesPopulator(AuthoritiesPopulator authoritiesPopulator) {
        this.authoritiesPopulator = authoritiesPopulator;
    }

    /* (non-Javadoc)
     * @see org.springframework.security.providers.AuthenticationProvider#supports(java.lang.Class)
     */
    public boolean supports(Class authentication) {
        return OpenIDAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
