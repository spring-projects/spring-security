/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.intercept.event;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.ConfigAttributeDefinition;


/**
 * Indicates a secure object invocation failed because the principal could not
 * be authenticated.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationFailureEvent extends SecurityInterceptionEvent {
    //~ Instance fields ========================================================

    private Authentication authentication;
    private AuthenticationException authenticationException;
    private ConfigAttributeDefinition configAttributeDefinition;

    //~ Constructors ===========================================================

    /**
     * Construct the event.
     *
     * @param secureObject the secure object
     * @param configAttribs that apply to the secure object
     * @param authentication that was found on the <code>ContextHolder</code>
     * @param authenticationException that was returned by the
     *        <code>AuthenticationManager</code>
     *
     * @throws IllegalArgumentException DOCUMENT ME!
     */
    public AuthenticationFailureEvent(Object secureObject,
        ConfigAttributeDefinition configAttribs, Authentication authentication,
        AuthenticationException authenticationException) {
        super(secureObject);

        if ((configAttribs == null) || (authentication == null)
            || (authenticationException == null)) {
            throw new IllegalArgumentException(
                "All parameters are required and cannot be null");
        }

        this.configAttributeDefinition = configAttribs;
        this.authentication = authentication;
        this.authenticationException = authenticationException;
    }

    //~ Methods ================================================================

    public Authentication getAuthentication() {
        return authentication;
    }

    public AuthenticationException getAuthenticationException() {
        return authenticationException;
    }

    public ConfigAttributeDefinition getConfigAttributeDefinition() {
        return configAttributeDefinition;
    }
}
