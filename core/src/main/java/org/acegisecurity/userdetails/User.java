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


/**
 * Models core user information retieved by an {@link AuthenticationDao}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class User {
    //~ Instance fields ========================================================

    private String password;
    private String username;
    private GrantedAuthority[] authorities;
    private boolean enabled;

    //~ Constructors ===========================================================

    /**
     * Construct the <code>User</code> with the details required by  {@link
     * DaoAuthenticationProvider}.
     *
     * @param username the username presented to the
     *        <code>DaoAuthenticationProvider</code>
     * @param password the password that should be presented to the
     *        <code>DaoAuthenticationProvider</code>
     * @param enabled set to <code>true</code> if the user is enabled
     * @param authorities the authorities that should be granted to the caller
     *        if they presented the correct username and password and the user
     *        is enabled
     *
     * @throws IllegalArgumentException if a <code>null</code> value was passed
     *         either as a parameter or as an element in the
     *         <code>GrantedAuthority[]</code> array
     */
    public User(String username, String password, boolean enabled,
        GrantedAuthority[] authorities) throws IllegalArgumentException {
        if ((username == null) || (password == null) || (authorities == null)) {
            throw new IllegalArgumentException(
                "Cannot pass null values to constructor");
        }

        for (int i = 0; i < authorities.length; i++) {
            if (authorities[i] == null) {
                throw new IllegalArgumentException("Granted authority element "
                    + i
                    + " is null - GrantedAuthority[] cannot contain any null elements");
            }
        }

        this.username = username;
        this.password = password;
        this.enabled = enabled;
        this.authorities = authorities;
    }

    protected User() {
        throw new IllegalArgumentException("Cannot use default constructor");
    }

    //~ Methods ================================================================

    public GrantedAuthority[] getAuthorities() {
        return authorities;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String getPassword() {
        return password;
    }

    public String getUsername() {
        return username;
    }
}
