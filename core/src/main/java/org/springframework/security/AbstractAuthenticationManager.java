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

package org.springframework.security;

import org.springframework.security.providers.AbstractAuthenticationToken;


/**
 * An abstract implementation of the {@link AuthenticationManager}.
 *
 * @author Wesley Hall
 * @version $Id$
 */
public abstract class AbstractAuthenticationManager implements AuthenticationManager {
    //~ Methods ========================================================================================================

    /**
     * <p>An implementation of the <code>authenticate</code> method that calls the abstract method
     * <code>doAuthenticatation</code> to do its work.</p>
     *  <p>If doAuthenticate throws an <code>AuthenticationException</code> then the exception is populated
     * with the failed <code>Authentication</code> object that failed.</p>
     *
     * @param authRequest the authentication request object
     *
     * @return a fully authenticated object including credentials
     *
     * @throws AuthenticationException if authentication fails
     */
    public final Authentication authenticate(Authentication authRequest)
        throws AuthenticationException {
        try {
            Authentication authResult = doAuthentication(authRequest);
            copyDetails(authRequest, authResult);

            return authResult;
        } catch (AuthenticationException e) {
            e.setAuthentication(authRequest);
            throw e;
        }
    }

    /**
     * Copies the authentication details from a source Authentication object to a destination one, provided the
     * latter does not already have one set.
     *
     * @param source source authentication
     * @param dest the destination authentication object
     */
    private void copyDetails(Authentication source, Authentication dest) {
        if ((dest instanceof AbstractAuthenticationToken) && (dest.getDetails() == null)) {
            AbstractAuthenticationToken token = (AbstractAuthenticationToken) dest;

            token.setDetails(source.getDetails());
        }
    }

    /**
     * <p>Concrete implementations of this class override this method to provide the authentication service.</p>
     *  <p>The contract for this method is documented in the {@link
     * AuthenticationManager#authenticate(org.springframework.security.Authentication)}.</p>
     *
     * @param authentication the authentication request object
     *
     * @return a fully authenticated object including credentials
     *
     * @throws AuthenticationException if authentication fails
     */
    protected abstract Authentication doAuthentication(Authentication authentication)
        throws AuthenticationException;
}
