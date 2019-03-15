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

package org.springframework.security.core;

/**
 * Abstract superclass for all exceptions related to an {@link Authentication} object being invalid for whatever
 * reason.
 *
 * @author Ben Alex
 */
public abstract class AuthenticationException extends RuntimeException {
    //~ Instance fields ================================================================================================

    private Authentication authentication;
    private transient Object extraInformation;

    //~ Constructors ===================================================================================================

    /**
     * Constructs an {@code AuthenticationException} with the specified message and root cause.
     *
     * @param msg the detail message
     * @param t the root cause
     */
    public AuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }

    /**
     * Constructs an {@code AuthenticationException} with the specified message and no root cause.
     *
     * @param msg the detail message
     */
    public AuthenticationException(String msg) {
        super(msg);
    }

    /**
     * @deprecated Use the exception message or use a custom exception if you really need additional information.
     */
    @Deprecated
    public AuthenticationException(String msg, Object extraInformation) {
        super(msg);
        if (extraInformation instanceof CredentialsContainer) {
            ((CredentialsContainer) extraInformation).eraseCredentials();
        }
        this.extraInformation = extraInformation;
    }

    //~ Methods ========================================================================================================

    /**
     * The authentication request which this exception corresponds to (may be {@code null})
     * @deprecated to avoid potential leaking of sensitive information (e.g. through serialization/remoting).
     */
    @Deprecated
    public Authentication getAuthentication() {
        return authentication;
    }

    @Deprecated
    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }

    /**
     * Any additional information about the exception. Generally a {@code UserDetails} object.
     *
     * @return extra information or {@code null}
     * @deprecated Use the exception message or use a custom exception if you really need additional information.
     */
    @Deprecated
    public Object getExtraInformation() {
        return extraInformation;
    }

    @Deprecated
    public void clearExtraInformation() {
        this.extraInformation = null;
    }
}
