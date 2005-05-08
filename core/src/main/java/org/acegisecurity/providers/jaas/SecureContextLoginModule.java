/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.context.SecurityContextHolder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;


/**
 * An implementation of {@link LoginModule} that uses an Acegi Security {@link
 * SecureContext} to provide authentication. <br>
 * This LoginModule provides opposite functionality to the {@link
 * JaasAuthenticationProvider} API, and should not really be used in
 * conjunction. <br>
 * The {@link JaasAuthenticationProvider} allows Acegi to authenticate against
 * Jaas. <br>
 * The SecureContextLoginModule allows a Jaas based application to
 * authenticate against Acegi.
 *
 * @author Brian Moseley
 * @author Ray Krueger
 */
public class SecureContextLoginModule implements LoginModule {
    //~ Static fields/initializers =============================================

    private static final Log log = LogFactory.getLog(SecureContextLoginModule.class);

    //~ Instance fields ========================================================

    private Authentication authen;
    private Subject subject;

    //~ Methods ================================================================

    /**
     * Abort the authentication process by forgetting the Acegi Security
     * <code>Authentication</code>.
     *
     * @return true if this method succeeded, or false if this
     *         <code>LoginModule</code> should be ignored.
     *
     * @exception LoginException if the abort fails
     */
    public boolean abort() throws LoginException {
        if (authen == null) {
            return false;
        }

        authen = null;

        return true;
    }

    /**
     * Authenticate the <code>Subject</code> (phase two) by adding the Acegi
     * Security <code>Authentication</code> to the <code>Subject</code>'s
     * principals.
     *
     * @return true if this method succeeded, or false if this
     *         <code>LoginModule</code> should be ignored.
     *
     * @exception LoginException if the commit fails
     */
    public boolean commit() throws LoginException {
        if (authen == null) {
            return false;
        }

        subject.getPrincipals().add(authen);

        return true;
    }

    /**
     * Initialize this <code>LoginModule</code>. Ignores the callback handler,
     * since the code establishing the <code>LoginContext</code> likely won't
     * provide one that understands Acegi Security. Also ignores the
     * <code>sharedState</code> and <code>options</code> parameters, since
     * none are recognized.
     *
     * @param subject the <code>Subject</code> to be authenticated. <p>
     * @param callbackHandler is ignored
     * @param sharedState is ignored
     * @param options are ignored
     */
    public void initialize(Subject subject, CallbackHandler callbackHandler,
        Map sharedState, Map options) {
        this.subject = subject;
    }

    /**
     * Authenticate the <code>Subject</code> (phase one) by extracting the
     * Acegi Security <code>Authentication</code> from the current
     * <code>SecureContext</code>.
     *
     * @return true if the authentication succeeded, or false if this
     *         <code>LoginModule</code> should be ignored.
     *
     * @throws LoginException if the authentication fails
     */
    public boolean login() throws LoginException {
        authen = SecurityContextHolder.getContext().getAuthentication();

        if (authen == null) {
            throw new LoginException("Authentication not found in security"
                + " context");
        }

        return true;
    }

    /**
     * Log out the <code>Subject</code>.
     *
     * @return true if this method succeeded, or false if this
     *         <code>LoginModule</code> should be ignored.
     *
     * @exception LoginException if the logout fails
     */
    public boolean logout() throws LoginException {
        if (authen == null) {
            return false;
        }

        subject.getPrincipals().remove(authen);
        authen = null;

        return true;
    }

    Authentication getAuthentication() {
        return authen;
    }

    Subject getSubject() {
        return subject;
    }
}
