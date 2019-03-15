/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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
 * Evaluates <code>Authentication</code> tokens
 *
 * @author Ben Alex
 */
public interface AuthenticationTrustResolver {
    //~ Methods ========================================================================================================

    /**
     * Indicates whether the passed <code>Authentication</code> token represents an anonymous user. Typically
     * the framework will call this method if it is trying to decide whether an <code>AccessDeniedException</code>
     * should result in a final rejection (i.e. as would be the case if the principal was non-anonymous/fully
     * authenticated) or direct the principal to attempt actual authentication (i.e. as would be the case if the
     * <code>Authentication</code> was merely anonymous).
     *
     * @param authentication to test (may be <code>null</code> in which case the method will always return
     *        <code>false</code>)
     *
     * @return <code>true</code> the passed authentication token represented an anonymous principal, <code>false</code>
     *         otherwise
     */
    boolean isAnonymous(Authentication authentication);

    /**
     * Indicates whether the passed <code>Authentication</code> token represents user that has been remembered
     * (i.e. not a user that has been fully authenticated).
     * <p>
     * The method is provided to assist with custom <code>AccessDecisionVoter</code>s and the like that you
     * might develop. Of course, you don't need to use this method either and can develop your own "trust level"
     * hierarchy instead.
     *
     * @param authentication to test (may be <code>null</code> in which case the method will always return
     *        <code>false</code>)
     *
     * @return <code>true</code> the passed authentication token represented a principal authenticated using a
     *         remember-me token, <code>false</code> otherwise
     */
    boolean isRememberMe(Authentication authentication);
}
