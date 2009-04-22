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

package org.springframework.security.authentication;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;


/**
 * Represents a remembered <code>Authentication</code>.
 * <p>
 * A remembered <code>Authentication</code> must provide a fully valid <code>Authentication</code>, including the
 * <code>GrantedAuthority</code>s that apply.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RememberMeAuthenticationToken extends AbstractAuthenticationToken implements Serializable {
    //~ Instance fields ================================================================================================

    private final Object principal;
    private final int keyHash;

    //~ Constructors ===================================================================================================

    /**
     * @deprecated
     */
    public RememberMeAuthenticationToken(String key, Object principal, GrantedAuthority[] authorities) {
        this(key, principal, Arrays.asList(authorities));
    }

    /**
     * Constructor.
     *
     * @param key to identify if this object made by an authorised client
     * @param principal the principal (typically a <code>UserDetails</code>)
     * @param authorities the authorities granted to the principal
     *
     * @throws IllegalArgumentException if a <code>null</code> was passed
     */
    public RememberMeAuthenticationToken(String key, Object principal, List<GrantedAuthority> authorities) {
        super(authorities);

        if ((key == null) || ("".equals(key)) || (principal == null) || "".equals(principal)) {
            throw new IllegalArgumentException("Cannot pass null or empty values to constructor");
        }

        this.keyHash = key.hashCode();
        this.principal = principal;
        setAuthenticated(true);
    }

    //~ Methods ========================================================================================================

    public boolean equals(Object obj) {
        if (!super.equals(obj)) {
            return false;
        }

        if (obj instanceof RememberMeAuthenticationToken) {
            RememberMeAuthenticationToken test = (RememberMeAuthenticationToken) obj;

            if (this.getKeyHash() != test.getKeyHash()) {
                return false;
            }

            return true;
        }

        return false;
    }

    /**
     * Always returns an empty <code>String</code>
     *
     * @return an empty String
     */
    public Object getCredentials() {
        return "";
    }

    public int getKeyHash() {
        return this.keyHash;
    }

    public Object getPrincipal() {
        return this.principal;
    }
}
