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

package org.springframework.security.authentication.jaas;

import org.springframework.security.core.Authentication;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;


/**
 * The JaasAuthenticationCallbackHandler is similar to the
 * javax.security.auth.callback.CallbackHandler interface in that it defines a
 * handle method. The JaasAuthenticationCallbackHandler is only asked to
 * handle one Callback instance at at time rather than an array of all
 * Callbacks, as the javax... CallbackHandler defines.
 *
 * <p>
 * Before a JaasAuthenticationCallbackHandler is asked to 'handle' any
 * callbacks, it is first passed the Authentication object that the login
 * attempt is for. NOTE: The Authentication object has not been
 * 'authenticated' yet.
 * </p>
 *
 * @author Ray Krueger
 * @version $Id$
 *
 * @see JaasNameCallbackHandler
 * @see JaasPasswordCallbackHandler
 * @see <a
 *      href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/Callback.html">Callback</a>
 * @see <a href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/CallbackHandler.html">
 *      CallbackHandler</a>
 */
public interface JaasAuthenticationCallbackHandler {
    //~ Methods ========================================================================================================

    /**
     * Handle the <a
     * href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/Callback.html">Callback</a>. The
     * handle method will be called for every callback instance sent from the LoginContext. Meaning that The handle
     * method may be called multiple times for a given JaasAuthenticationCallbackHandler.
     *
     * @param callback
     * @param auth The Authentication object currently being authenticated.
     *
     * @throws IOException
     * @throws UnsupportedCallbackException
     */
    void handle(Callback callback, Authentication auth)
        throws IOException, UnsupportedCallbackException;
}
