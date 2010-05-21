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

package org.springframework.security.cas.authentication;

import java.io.Serializable;
import java.util.Collection;

import org.jasig.cas.client.validation.Assertion;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Represents a successful CAS <code>Authentication</code>.
 *
 * @author Ben Alex
 * @author Scott Battaglia
 */
public class CasAuthenticationToken extends AbstractAuthenticationToken implements Serializable {
    //~ Instance fields ================================================================================================

    private static final long serialVersionUID = 1L;
    private final Object credentials;
    private final Object principal;
    private final UserDetails userDetails;
    private final int keyHash;
    private final Assertion assertion;

    //~ Constructors ===================================================================================================

    /**
     * Constructor.
     *
     * @param key to identify if this object made by a given {@link
     *        CasAuthenticationProvider}
     * @param principal typically the UserDetails object (cannot  be <code>null</code>)
     * @param credentials the service/proxy ticket ID from CAS (cannot be
     *        <code>null</code>)
     * @param authorities the authorities granted to the user (from the {@link
     *        org.springframework.security.core.userdetails.UserDetailsService}) (cannot be <code>null</code>)
     * @param userDetails the user details (from the {@link
     *        org.springframework.security.core.userdetails.UserDetailsService}) (cannot be <code>null</code>)
     * @param assertion the assertion returned from the CAS servers.  It contains the principal and how to obtain a
     *        proxy ticket for the user.
     *
     * @throws IllegalArgumentException if a <code>null</code> was passed
     */
    public CasAuthenticationToken(final String key, final Object principal, final Object credentials,
        final Collection<? extends GrantedAuthority> authorities, final UserDetails userDetails, final Assertion assertion) {
        super(authorities);

        if ((key == null) || ("".equals(key)) || (principal == null) || "".equals(principal) || (credentials == null)
            || "".equals(credentials) || (authorities == null) || (userDetails == null) || (assertion == null)) {
            throw new IllegalArgumentException("Cannot pass null or empty values to constructor");
        }

        this.keyHash = key.hashCode();
        this.principal = principal;
        this.credentials = credentials;
        this.userDetails = userDetails;
        this.assertion = assertion;
        setAuthenticated(true);
    }

    //~ Methods ========================================================================================================

    public boolean equals(final Object obj) {
        if (!super.equals(obj)) {
            return false;
        }

        if (obj instanceof CasAuthenticationToken) {
            CasAuthenticationToken test = (CasAuthenticationToken) obj;

            if (!this.assertion.equals(test.getAssertion())) {
                return false;
            }

            if (this.getKeyHash() != test.getKeyHash()) {
                return false;
            }

            return true;
        }

        return false;
    }

    public Object getCredentials() {
        return this.credentials;
    }

    public int getKeyHash() {
        return this.keyHash;
    }

    public Object getPrincipal() {
        return this.principal;
    }

    public Assertion getAssertion() {
        return this.assertion;
    }

    public UserDetails getUserDetails() {
        return userDetails;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString());
        sb.append(" Assertion: ").append(this.assertion);
        sb.append(" Credentials (Service/Proxy Ticket): ").append(this.credentials);

        return (sb.toString());
    }
}
