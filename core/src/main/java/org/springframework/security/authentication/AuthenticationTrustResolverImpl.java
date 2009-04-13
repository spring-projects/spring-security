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

package org.springframework.security.authentication;

import org.springframework.security.core.Authentication;


/**
 * Basic implementation of {@link AuthenticationTrustResolver}.
 * <p>
 * Makes trust decisions based on whether the passed <code>Authentication</code> is an instance of a defined class.
 * <p>
 * If {@link #anonymousClass} or {@link #rememberMeClass} is <code>null</code>, the corresponding method will
 * always return <code>false</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationTrustResolverImpl implements AuthenticationTrustResolver {
    //~ Instance fields ================================================================================================

    private Class<? extends Authentication> anonymousClass = AnonymousAuthenticationToken.class;
    private Class<? extends Authentication> rememberMeClass = RememberMeAuthenticationToken.class;

    //~ Methods ========================================================================================================

    Class<? extends Authentication> getAnonymousClass() {
        return anonymousClass;
    }

    Class<? extends Authentication> getRememberMeClass() {
        return rememberMeClass;
    }

    public boolean isAnonymous(Authentication authentication) {
        if ((anonymousClass == null) || (authentication == null)) {
            return false;
        }

        return anonymousClass.isAssignableFrom(authentication.getClass());
    }

    public boolean isRememberMe(Authentication authentication) {
        if ((rememberMeClass == null) || (authentication == null)) {
            return false;
        }

        return rememberMeClass.isAssignableFrom(authentication.getClass());
    }

    public void setAnonymousClass(Class<? extends Authentication> anonymousClass) {
        this.anonymousClass = anonymousClass;
    }

    public void setRememberMeClass(Class<? extends Authentication> rememberMeClass) {
        this.rememberMeClass = rememberMeClass;
    }
}
