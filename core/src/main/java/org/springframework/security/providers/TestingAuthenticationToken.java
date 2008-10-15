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

package org.springframework.security.providers;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.util.AuthorityUtils;


/**
 * An {@link org.springframework.security.Authentication} implementation that is designed for use whilst unit testing.
 * <p>
 * The corresponding authentication provider is  {@link TestingAuthenticationProvider}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class TestingAuthenticationToken extends AbstractAuthenticationToken {
    //~ Instance fields ================================================================================================

    private static final long serialVersionUID = 1L;
    private Object credentials;
    private Object principal;

    //~ Constructors ===================================================================================================

    public TestingAuthenticationToken(Object principal, Object credentials) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
    }


    public TestingAuthenticationToken(Object principal, Object credentials, String... authorities) {
        this(principal, credentials, AuthorityUtils.stringArrayToAuthorityArray(authorities));
    }

    public TestingAuthenticationToken(Object principal, Object credentials, GrantedAuthority[] authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
    }

    //~ Methods ========================================================================================================

    public Object getCredentials() {
        return this.credentials;
    }

    public Object getPrincipal() {
        return this.principal;
    }
}
