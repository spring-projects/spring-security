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

package org.springframework.security.access.event;

import java.util.Collection;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;


/**
 * Indicates a secure object invocation failed because the principal could not
 * be authorized for the request.
 *
 * <p>This event might be thrown as a result of either an
 * {@link org.springframework.security.access.AccessDecisionManager AccessDecisionManager} or an
 * {@link org.springframework.security.access.intercept.AfterInvocationManager AfterInvocationManager}.
 *
 * @author Ben Alex
 */
public class AuthorizationFailureEvent extends AbstractAuthorizationEvent {
    //~ Instance fields ================================================================================================

    private AccessDeniedException accessDeniedException;
    private Authentication authentication;
    private Collection<ConfigAttribute> configAttributes;

    //~ Constructors ===================================================================================================

    /**
     * Construct the event.
     *
     * @param secureObject the secure object
     * @param attributes that apply to the secure object
     * @param authentication that was found in the <code>SecurityContextHolder</code>
     * @param accessDeniedException that was returned by the
     *        <code>AccessDecisionManager</code>
     *
     * @throws IllegalArgumentException if any null arguments are presented.
     */
    public AuthorizationFailureEvent(Object secureObject, Collection<ConfigAttribute> attributes,
        Authentication authentication, AccessDeniedException accessDeniedException) {
        super(secureObject);

        if ((attributes == null) || (authentication == null) || (accessDeniedException == null)) {
            throw new IllegalArgumentException("All parameters are required and cannot be null");
        }

        this.configAttributes = attributes;
        this.authentication = authentication;
        this.accessDeniedException = accessDeniedException;
    }

    //~ Methods ========================================================================================================

    public AccessDeniedException getAccessDeniedException() {
        return accessDeniedException;
    }

    public Authentication getAuthentication() {
        return authentication;
    }

    public Collection<ConfigAttribute> getConfigAttributes() {
        return configAttributes;
    }
}
