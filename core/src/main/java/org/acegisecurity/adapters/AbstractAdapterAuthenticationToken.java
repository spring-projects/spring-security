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

package net.sf.acegisecurity.adapters;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.providers.AbstractAuthenticationToken;


/**
 * Convenience superclass for {@link AuthByAdapter} implementations.
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AbstractAdapterAuthenticationToken
    extends AbstractAuthenticationToken implements AuthByAdapter {
    //~ Instance fields ========================================================

    private GrantedAuthority[] authorities;
    private int keyHash;

    //~ Constructors ===========================================================

    protected AbstractAdapterAuthenticationToken() {
        super();
    }

    /**
     * The only way an <code>AbstractAdapterAuthentication</code> should be
     * constructed.
     *
     * @param key the key that is hashed and made available via  {@link
     *        #getKeyHash()}
     * @param authorities the authorities granted to this principal
     */
    protected AbstractAdapterAuthenticationToken(String key,
        GrantedAuthority[] authorities) {
        super();
        this.keyHash = key.hashCode();
        this.authorities = authorities;
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
        return authorities;
    }

    public int getKeyHash() {
        return this.keyHash;
    }

    /**
     * Iterates the granted authorities and indicates whether or not the
     * specified role is held.
     * 
     * <p>
     * Comparison is based on the <code>String</code> returned by {@link
     * GrantedAuthority#getAuthority}.
     * </p>
     *
     * @param role the role being searched for in this object's granted
     *        authorities list
     *
     * @return <code>true</code> if the granted authority is held, or
     *         <code>false</code> otherwise
     */
    public boolean isUserInRole(String role) {
        for (int i = 0; i < this.authorities.length; i++) {
            if (role.equals(this.authorities[i].getAuthority())) {
                return true;
            }
        }

        return false;
    }

    public boolean equals(Object obj) {
        if (obj instanceof AbstractAdapterAuthenticationToken) {
            if (!super.equals(obj)) {
                return false;
            }

            AbstractAdapterAuthenticationToken test = (AbstractAdapterAuthenticationToken) obj;

            return (this.getKeyHash() == test.getKeyHash());
        }

        return false;
    }
}
