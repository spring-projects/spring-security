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

package org.springframework.security.access.intercept;

import java.util.Arrays;
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;


/**
 * An immutable {@link org.springframework.security.core.Authentication}  implementation that supports {@link RunAsManagerImpl}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RunAsUserToken extends AbstractAuthenticationToken {
    //~ Instance fields ================================================================================================

    private final Class<? extends Authentication> originalAuthentication;
    private final Object credentials;
    private final Object principal;
    private final int keyHash;

    //~ Constructors ===================================================================================================

    public RunAsUserToken(String key, Object principal, Object credentials, GrantedAuthority[] authorities,
            Class<? extends Authentication> originalAuthentication) {
        this(key, principal, credentials, Arrays.asList(authorities), originalAuthentication);
    }

    public RunAsUserToken(String key, Object principal, Object credentials, Collection<GrantedAuthority> authorities,
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
