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

package net.sf.acegisecurity.runas;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.providers.AbstractAuthenticationToken;


/**
 * An immutable {@link net.sf.acegisecurity.Authentication}  implementation
 * that supports {@link RunAsManagerImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RunAsUserToken extends AbstractAuthenticationToken {
    //~ Instance fields ========================================================

    private Class originalAuthentication;
    private Object credentials;
    private Object principal;
    private GrantedAuthority[] authorities;
    private int keyHash;

    //~ Constructors ===========================================================

    public RunAsUserToken(String key, Object principal, Object credentials,
        GrantedAuthority[] authorities, Class originalAuthentication) {
        super();
        this.keyHash = key.hashCode();
        this.authorities = authorities;
        this.principal = principal;
        this.credentials = credentials;
        this.originalAuthentication = originalAuthentication;
    }

    private RunAsUserToken() {
        super();
    }

    //~ Methods ================================================================

    /**
     * Setting is ignored. Always considered authenticated.
     *
     * @param ignored DOCUMENT ME!
     */
    public void setAuthenticated(boolean ignored) {
        // ignored
    }

    /**
     * Always returns <code>true</code>.
     *
     * @return DOCUMENT ME!
     */
    public boolean isAuthenticated() {
        return true;
    }

    public GrantedAuthority[] getAuthorities() {
        return this.authorities;
    }

    public Object getCredentials() {
        return this.credentials;
    }

    public int getKeyHash() {
        return this.keyHash;
    }

    public Class getOriginalAuthentication() {
        return this.originalAuthentication;
    }

    public Object getPrincipal() {
        return this.principal;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer(super.toString());
        sb.append("; Original Class: " + this.originalAuthentication.getName());

        return sb.toString();
    }
}
