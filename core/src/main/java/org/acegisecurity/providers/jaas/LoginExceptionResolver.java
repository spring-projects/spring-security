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

package org.acegisecurity.providers.jaas;

import org.acegisecurity.AcegiSecurityException;

import javax.security.auth.login.LoginException;


/**
 * The JaasAuthenticationProvider takes an instance of LoginExceptionResolver
 * to resolve LoginModule specific exceptions to Acegi exceptions.  For
 * instance, a configured login module could throw a
 * ScrewedUpPasswordException that extends LoginException, in this instance
 * the LoginExceptionResolver implementation would return a {@link
 * org.acegisecurity.BadCredentialsException}.
 *
 * @author Ray Krueger
 * @version $Revision$
 */
public interface LoginExceptionResolver {
    //~ Methods ========================================================================================================

    /**
     * Translates a Jaas LoginException to an AcegiSecurityException.
     *
     * @param e The LoginException thrown by the configured LoginModule.
     *
     * @return The AcegiSecurityException that the JaasAuthenticationProvider should throw.
     */
    AcegiSecurityException resolveException(LoginException e);
}
