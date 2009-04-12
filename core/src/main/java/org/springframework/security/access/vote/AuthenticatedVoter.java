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

package org.springframework.security.access.vote;

import java.util.List;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationTrustResolver;
import org.springframework.security.AuthenticationTrustResolverImpl;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.util.Assert;


/**
 * Votes if a {@link ConfigAttribute#getAttribute()} of <code>IS_AUTHENTICATED_FULLY</code> or
 * <code>IS_AUTHENTICATED_REMEMBERED</code> or <code>IS_AUTHENTICATED_ANONYMOUSLY</code> is present. This list is in
 * order of most strict checking to least strict checking.
 * <p>
 * The current <code>Authentication</code> will be inspected to determine if the principal has a particular
 * level of authentication. The "FULLY" authenticated option means the user is authenticated fully (i.e. {@link
 * org.springframework.security.AuthenticationTrustResolver#isAnonymous(Authentication)} is false and {@link
 * org.springframework.security.AuthenticationTrustResolver#isRememberMe(Authentication)} is false). The "REMEMBERED" will grant
 * access if the principal was either authenticated via remember-me OR is fully authenticated. The "ANONYMOUSLY" will
 * grant access if the principal was authenticated via remember-me, OR anonymously, OR via full authentication.
 * <p>
 * All comparisons and prefixes are case sensitive.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticatedVoter implements AccessDecisionVoter {
    //~ Static fields/initializers =====================================================================================

    public static final String IS_AUTHENTICATED_FULLY = "IS_AUTHENTICATED_FULLY";
    public static final String IS_AUTHENTICATED_REMEMBERED = "IS_AUTHENTICATED_REMEMBERED";
    public static final String IS_AUTHENTICATED_ANONYMOUSLY = "IS_AUTHENTICATED_ANONYMOUSLY";
    //~ Instance fields ================================================================================================

    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

    //~ Methods ========================================================================================================

    private boolean isFullyAuthenticated(Authentication authentication) {
        return (!authenticationTrustResolver.isAnonymous(authentication) &&
                !authenticationTrustResolver.isRememberMe(authentication));
    }

    public void setAuthenticationTrustResolver(AuthenticationTrustResolver authenticationTrustResolver) {
        Assert.notNull(authenticationTrustResolver, "AuthenticationTrustResolver cannot be set to null");
        this.authenticationTrustResolver = authenticationTrustResolver;
    }

    public boolean supports(ConfigAttribute attribute) {
        if ((attribute.getAttribute() != null)
            && (IS_AUTHENTICATED_FULLY.equals(attribute.getAttribute())
            || IS_AUTHENTICATED_REMEMBERED.equals(attribute.getAttribute())
            || IS_AUTHENTICATED_ANONYMOUSLY.equals(attribute.getAttribute()))) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * This implementation supports any type of class, because it does not query the presented secure object.
     *
     * @param clazz the secure object
     *
     * @return always <code>true</code>
     */
    public boolean supports(Class<?> clazz) {
        return true;
    }

    public int vote(Authentication authentication, Object object, List<ConfigAttribute> attributes) {
        int result = ACCESS_ABSTAIN;

        for (ConfigAttribute attribute : attributes) {
            if (this.supports(attribute)) {
                result = ACCESS_DENIED;

                if (IS_AUTHENTICATED_FULLY.equals(attribute.getAttribute())) {
                    if (isFullyAuthenticated(authentication)) {
                        return ACCESS_GRANTED;
                    }
                }

                if (IS_AUTHENTICATED_REMEMBERED.equals(attribute.getAttribute())) {
                    if (authenticationTrustResolver.isRememberMe(authentication)
                        || isFullyAuthenticated(authentication)) {
                        return ACCESS_GRANTED;
                    }
                }

                if (IS_AUTHENTICATED_ANONYMOUSLY.equals(attribute.getAttribute())) {
                    if (authenticationTrustResolver.isAnonymous(authentication) || isFullyAuthenticated(authentication)
                        || authenticationTrustResolver.isRememberMe(authentication)) {
                        return ACCESS_GRANTED;
                    }
                }
            }
        }

        return result;
    }
}
