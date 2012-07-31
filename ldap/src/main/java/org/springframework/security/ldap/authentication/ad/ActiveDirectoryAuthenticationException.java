/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.ldap.authentication.ad;

import org.springframework.security.core.AuthenticationException;

/**
 * <p>
 * Thrown as a translation of an {@link javax.naming.AuthenticationException} when attempting to authenticate against
 * Active Directory using {@link ActiveDirectoryLdapAuthenticationProvider}. Typically this error is wrapped by an
 * {@link AuthenticationException} since it does not provide a user friendly message. When wrapped, the original
 * Exception can be caught and {@link ActiveDirectoryAuthenticationException} can be accessed using
 * {@link AuthenticationException#getCause()} for custom error handling.
 * </p>
 * <p>
 * The {@link #getDataCode()} will return the error code associated with the data portion of the error message. For
 * example, the following error message would return 773 for {@link #getDataCode()}.
 * </p>
 *
 * <pre>
 * javax.naming.AuthenticationException: [LDAP: error code 49 - 80090308: LdapErr: DSID-0C090334, comment: AcceptSecurityContext error, data 775, vece ]
 * </pre>
 *
 * @author Rob Winch
 */
@SuppressWarnings("serial")
public final class ActiveDirectoryAuthenticationException extends AuthenticationException {
    private final String dataCode;

    ActiveDirectoryAuthenticationException(String dataCode, String message, Throwable cause) {
        super(message, cause);
        this.dataCode = dataCode;
    }

    public String getDataCode() {
        return dataCode;
    }
}
