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

package net.sf.acegisecurity.providers.x509;

import net.sf.acegisecurity.providers.AbstractAuthenticationToken;
import net.sf.acegisecurity.GrantedAuthority;

import java.security.cert.X509Certificate;

/**
 * <code>Authentication</code> implementation for X.509 client-certificate authentication.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class X509AuthenticationToken extends AbstractAuthenticationToken {
    //~ Instance fields ========================================================

    private X509Certificate credentials;
    private Object principal;
    private GrantedAuthority[] authorities;
    private boolean authenticated = false;
    private Object details = null;

    //~ Constructors ===========================================================

    /** Used for an authentication request */
    public X509AuthenticationToken(X509Certificate credentials) {
        this.credentials = credentials;
    }

    public X509AuthenticationToken(Object principal, X509Certificate credentials, GrantedAuthority[] authorities) {
        this.credentials = credentials;
        this.principal = principal;
        this.authorities = authorities;
    }

    //~ Methods ================================================================

    public Object getDetails() {
        return details;
    }

    public void setDetails(Object details) {
        this.details = details;
    }


    public void setAuthenticated(boolean isAuthenticated) {
        this.authenticated = isAuthenticated;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public GrantedAuthority[] getAuthorities() {
        return authorities;
    }

    public Object getCredentials() {
        return credentials;
    }

    public Object getPrincipal() {
        return principal;
    }
}
