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

package net.sf.acegisecurity;

/**
 * Abstract superclass for all exceptions related an {@link Authentication}
 * object being invalid for whatever reason.
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AuthenticationException extends AcegiSecurityException {
    //~ Instance fields ========================================================

    /**
     * The authentication that related to this exception (may be
     * <code>null</code>)
     */
    private Authentication authentication;

    //~ Constructors ===========================================================

    /**
     * Constructs an <code>AuthenticationException</code> with the specified
     * message and root cause.
     *
     * @param msg the detail message
     * @param t the root cause
     */
    public AuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }

    /**
     * Constructs an <code>AuthenticationException</code> with the specified
     * message and no root cause.
     *
     * @param msg the detail message
     */
    public AuthenticationException(String msg) {
        super(msg);
    }

    //~ Methods ================================================================

    public Authentication getAuthentication() {
        return authentication;
    }

    void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }
}
