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

package org.springframework.security.runas;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;

import org.springframework.security.providers.AbstractAuthenticationToken;


/**
 * An immutable {@link org.springframework.security.Authentication}  implementation that supports {@link RunAsManagerImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RunAsUserToken extends AbstractAuthenticationToken {
    //~ Instance fields ================================================================================================

    private static final long serialVersionUID = 1L;
    private Class<? extends Authentication> originalAuthentication;
    private Object credentials;
    private Object principal;
    private int keyHash;

    //~ Constructors ===================================================================================================

    public RunAsUserToken(String key, Object principal, Object credentials, GrantedAuthority[] authorities,
            Class<? extends Authentication> originalAuthentication) {
        this(key, principal, credentials, Arrays.asList(authorities), originalAuthentication);
    }

    public RunAsUserToken(String key, Object principal, Object credentials, List<GrantedAuthority> authorities,
            Class<? extends Authentication> originalAuthentication) {
        super(authorities);
        this.keyHash = key.hashCode();
        this.principal = principal;
        this.credentials = credentials;
        this.originalAuthentication = originalAuthentication;
        setAuthenticated(true);
    }

    //~ Methods ========================================================================================================

    public Object getCredentials() {
        return this.credentials;
    }

    public int getKeyHash() {
        return this.keyHash;
    }

    public Class<? extends Authentication> getOriginalAuthentication() {
        return this.originalAuthentication;
    }

    public Object getPrincipal() {
        return this.principal;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer(super.toString());
        sb.append("; Original Class: ").append(this.originalAuthentication.getName());

        return sb.toString();
    }
}
