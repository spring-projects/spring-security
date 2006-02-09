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

package org.acegisecurity.providers.x509;

import org.acegisecurity.GrantedAuthority;

import org.acegisecurity.providers.AbstractAuthenticationToken;

import java.security.cert.X509Certificate;


/**
 * <code>Authentication</code> implementation for X.509 client-certificate
 * authentication.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class X509AuthenticationToken extends AbstractAuthenticationToken {
    //~ Instance fields ========================================================

    private Object principal;
    private X509Certificate credentials;

    //~ Constructors ===========================================================

    /**
     * Used for an authentication request
     *
     * @param credentials DOCUMENT ME!
     */
    public X509AuthenticationToken(X509Certificate credentials) {
        super(null);
        this.credentials = credentials;
    }

    public X509AuthenticationToken(Object principal,
        X509Certificate credentials, GrantedAuthority[] authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
    }

    //~ Methods ================================================================

    public Object getCredentials() {
        return credentials;
    }

    public Object getPrincipal() {
        return principal;
    }
}
