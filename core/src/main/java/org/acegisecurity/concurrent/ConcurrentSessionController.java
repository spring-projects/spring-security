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

package org.acegisecurity.concurrent;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;


/**
 * Provides two methods that can be called by an {@link
 * org.acegisecurity.AuthenticationManager} to integrate with the
 * concurrent session handling infrastructure.
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface ConcurrentSessionController {
    //~ Methods ========================================================================================================

    /**
     * Called by any class that wishes to know whether the current authentication request should be permitted.
     * Generally callers will be <code>AuthenticationManager</code>s before they authenticate, but could equally
     * include <code>Filter</code>s or other interceptors that wish to confirm the ongoing validity of a previously
     * authenticated <code>Authentication</code>.<p>The implementation should throw a suitable exception if the
     * user has exceeded their maximum allowed concurrent sessions.</p>
     *
     * @param request the authentication request (never <code>null</code>)
     *
     * @throws AuthenticationException if the user has exceeded their maximum allowed current sessions
     */
    public void checkAuthenticationAllowed(Authentication request)
        throws AuthenticationException;

    /**
     * Called by an <code>AuthenticationManager</code> when the authentication was successful. An
     * implementation is expected to register the authenticated user in some sort of registry, for future concurrent
     * tracking via the {@link #checkAuthenticationAllowed(Authentication)} method.
     *
     * @param authentication the successfully authenticated user (never <code>null</code>)
     */
    public void registerSuccessfulAuthentication(Authentication authentication);
}
