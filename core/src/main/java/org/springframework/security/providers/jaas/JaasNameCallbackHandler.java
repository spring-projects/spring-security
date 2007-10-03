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

package org.springframework.security.providers.jaas;

import org.springframework.security.Authentication;

import org.springframework.security.userdetails.UserDetails;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;


/**
 * The most basic Callbacks to be handled when using a LoginContext from JAAS, are the NameCallback and
 * PasswordCallback. Spring Security provides the JaasNameCallbackHandler specifically tailored to
 * handling the NameCallback. <br>
 *
 * @author Ray Krueger
 * @version $Id$
 *
 * @see <a href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/Callback.html">Callback</a>
 * @see <a
 *      href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/NameCallback.html">NameCallback</a>
 */
public class JaasNameCallbackHandler implements JaasAuthenticationCallbackHandler {
    //~ Methods ========================================================================================================

    /**
     * If the callback passed to the 'handle' method is an instance of NameCallback, the
     * JaasNameCallbackHandler will call, callback.setName(authentication.getPrincipal().toString()).
     *
     * @param callback
     * @param authentication
     *
     * @throws IOException
     * @throws UnsupportedCallbackException
     */
    public void handle(Callback callback, Authentication authentication)
        throws IOException, UnsupportedCallbackException {
        if (callback instanceof NameCallback) {
            NameCallback ncb = (NameCallback) callback;
            String username = "";

            Object principal = authentication.getPrincipal();

            if (principal instanceof UserDetails) {
                username = ((UserDetails) principal).getUsername();
            } else {
                username = principal.toString();
            }

            ncb.setName(username);
        }
    }
}
