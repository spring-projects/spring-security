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

package net.sf.acegisecurity.providers.dao;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.providers.AbstractAuthenticationToken;

import java.io.Serializable;

import java.util.Date;


/**
 * Represents a successful DAO-based <code>Authentication</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DaoAuthenticationToken extends AbstractAuthenticationToken
    implements Serializable {
    //~ Instance fields ========================================================

    private Date expires;
    private Object credentials;
    private Object principal;
    private GrantedAuthority[] authorities;
    private int keyHash;

    //~ Constructors ===========================================================

    /**
     * Constructor.
     *
     * @param key to identify if this object made by a given {@link
     *        DaoAuthenticationProvider}
     * @param expires when the token is due to expire
     * @param principal the username from the {@link User} object
     * @param credentials the password from the {@link User} object
     * @param authorities the authorities granted to the user, from the {@link
     *        User} object
     *
     * @throws IllegalArgumentException if a <code>null</code> was passed
     */
    public DaoAuthenticationToken(String key, Date expires, Object principal,
        Object credentials, GrantedAuthority[] authorities) {
        if ((key == null) || ("".equals(key)) || (expires == null)
            || (principal == null) || "".equals(principal)
            || (credentials == null) || "".equals(credentials)
            || (authorities == null)) {
            throw new IllegalArgumentException(
                "Cannot pass null or empty values to constructor");
        }

        for (int i = 0; i < authorities.length; i++) {
            if (authorities[i] == null) {
                throw new IllegalArgumentException("Granted authority element "
                    + i
                    + " is null - GrantedAuthority[] cannot contain any null elements");
            }
        }

        this.keyHash = key.hashCode();
        this.expires = expires;
        this.principal = principal;
        this.credentials = credentials;
        this.authorities = authorities;
    }

    protected DaoAuthenticationToken() {
        throw new IllegalArgumentException("Cannot use default constructor");
    }

    //~ Methods ================================================================

    /**
     * Ignored (always <code>true</code>).
     *
     * @param isAuthenticated ignored
     */
    public void setAuthenticated(boolean isAuthenticated) {
        // ignored
    }

    /**
     * Always returns <code>true</code>.
     *
     * @return true
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

    public Date getExpires() {
        return this.expires;
    }

    public int getKeyHash() {
        return this.keyHash;
    }

    public Object getPrincipal() {
        return this.principal;
    }

    public boolean equals(Object obj) {
        if (!super.equals(obj)) {
            return false;
        }

        if (obj instanceof DaoAuthenticationToken) {
            DaoAuthenticationToken test = (DaoAuthenticationToken) obj;

            if (this.getKeyHash() != test.getKeyHash()) {
                return false;
            }

            // expires never null due to constructor
            if (this.getExpires() != test.getExpires()) {
                return false;
            }

            return true;
        }

        return false;
    }
}
