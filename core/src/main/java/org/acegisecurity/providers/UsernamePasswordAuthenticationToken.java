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

package org.acegisecurity.providers;

import org.acegisecurity.GrantedAuthority;


/**
 * An {@link org.acegisecurity.Authentication} implementation that is designed for simple presentation of a
 * username and password.<p>The <code>principal</code> and <code>credentials</code> should be set with an
 * <code>Object</code> that provides the respective property via its <code>Object.toString()</code> method. The
 * simplest such <code>Object</code> to use is <code>String</code>.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UsernamePasswordAuthenticationToken extends AbstractAuthenticationToken {
    //~ Instance fields ================================================================================================

    private Object credentials;
    private Object principal;

    //~ Constructors ===================================================================================================

/**
     * This constructor can be safely used by any code that wishes to create a
     * <code>UsernamePasswordAuthenticationToken</code>, as the {@link
     * #isAuthenticated()} will return <code>false</code>.
     *
     * @param principal DOCUMENT ME!
     * @param credentials DOCUMENT ME!
     */
    public UsernamePasswordAuthenticationToken(Object principal, Object credentials) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(false);
    }

/**
     * This constructor should only be used by
     * <code>AuthenticationManager</code> or
     * <code>AuthenticationProvider</code> implementations that are satisfied
     * with producing a trusted (ie {@link #isAuthenticated()} =
     * <code>true</code>) authentication token.
     *
     * @param principal
     * @param credentials
     * @param authorities
     */
    public UsernamePasswordAuthenticationToken(Object principal, Object credentials, GrantedAuthority[] authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true); // must use super, as we override
    }

    //~ Methods ========================================================================================================

    public Object getCredentials() {
        return this.credentials;
    }

    public Object getPrincipal() {
        return this.principal;
    }

    public void setAuthenticated(boolean isAuthenticated)
        throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                "Cannot set this token to trusted - use constructor containing GrantedAuthority[]s instead");
        }

        super.setAuthenticated(false);
    }
}
