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

package org.acegisecurity.providers.jaas.event;

import org.acegisecurity.Authentication;


/**
 * Fired when LoginContext.login throws a LoginException, or if any other
 * exception is thrown during that time.
 *
 * @author Ray Krueger
 * @version $Id$
 */
public class JaasAuthenticationFailedEvent extends JaasAuthenticationEvent {
    //~ Instance fields ========================================================

    private Exception exception;

    //~ Constructors ===========================================================

    public JaasAuthenticationFailedEvent(Authentication auth,
        Exception exception) {
        super(auth);
        this.exception = exception;
    }

    //~ Methods ================================================================

    public Exception getException() {
        return exception;
    }
}
