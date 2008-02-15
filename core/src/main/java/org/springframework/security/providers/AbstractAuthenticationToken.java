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

package org.springframework.security.providers;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.util.Assert;


/**
 * Base class for <code>Authentication</code> objects.<p>Implementations which use this class should be immutable.</p>
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AbstractAuthenticationToken implements Authentication {
    //~ Instance fields ================================================================================================

    private Object details;
    private GrantedAuthority[] authorities;
    private boolean authenticated = false;

    //~ Constructors ===================================================================================================

    /**
     * Retained for compatibility with subclasses written before the
     * <tt>AbstractAuthenticationToken(GrantedAuthority[])</tt> constructor
     * was introduced.
     *
     * @deprecated in favour of the constructor which takes a
     *             <code>GrantedAuthority[]</code> argument.
     */
    public AbstractAuthenticationToken() {
    }

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the list of <tt>GrantedAuthority</tt>s for the
     *                    principal represented by this authentication object. A
     *                    <code>null</code> value indicates that no authorities have been
     *                    granted (pursuant to the interface contract specified by {@link
     *                    Authentication#getAuthorities()}<code>null</code> should only be
     *                    presented if the principal has not been authenticated).
     */
    public AbstractAuthenticationToken(GrantedAuthority[] authorities) {
        if (authorities != null) {
            for (int i = 0; i < authorities.length; i++) {
                Assert.notNull(authorities[i],
                        "Granted authority element " + i + " is null - GrantedAuthority[] cannot contain any null elements");
            }
        }

        this.authorities = authorities;
    }

    //~ Methods ========================================================================================================

    public boolean equals(Object obj) {
        if (obj instanceof AbstractAuthenticationToken) {
            AbstractAuthenticationToken test = (AbstractAuthenticationToken) obj;

            if (!((this.getAuthorities() == null) && (test.getAuthorities() == null))) {
                if ((this.getAuthorities() == null) || (test.getAuthorities() == null)) {
                    return false;
                }

                if (this.getAuthorities().length != test.getAuthorities().length) {
                    return false;
                }

                for (int i = 0; i < this.getAuthorities().length; i++) {
                    if (!this.getAuthorities()[i].equals(test.getAuthorities()[i])) {
                        return false;
                    }
                }
            }

            if ((this.details == null) && (test.getDetails() != null)) {
                return false;
            }

            if ((this.details != null) && (test.getDetails() == null)) {
                return false;
            }

            if ((this.details != null) && (!this.details.equals(test.getDetails()))) {
                return false;
            }

            if ((this.getCredentials() == null) && (test.getCredentials() != null)) {
                return false;
            }

            if ((this.getCredentials() != null) && !this.getCredentials().equals(test.getCredentials())) {
                return false;
            }

            return (this.getPrincipal().equals(test.getPrincipal())
                    && (this.isAuthenticated() == test.isAuthenticated()));
        }

        return false;
    }

    public GrantedAuthority[] getAuthorities() {
        if (authorities == null) {
            return null;
        }

        GrantedAuthority[] copy = new GrantedAuthority[authorities.length];
        System.arraycopy(authorities, 0, copy, 0, authorities.length);

        return copy;
    }

    public Object getDetails() {
        return details;
    }

    public String getName() {
        if (this.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) this.getPrincipal()).getUsername();
        }

        return (this.getPrincipal() == null) ? "" : this.getPrincipal().toString();
    }

    public int hashCode() {
        int code = 31;

        // Copy authorities to local variable for performance (SEC-223)
        GrantedAuthority[] authorities = this.getAuthorities();

        if (authorities != null) {
            for (int i = 0; i < authorities.length; i++) {
                code ^= authorities[i].hashCode();
            }
        }

        if (this.getPrincipal() != null) {
            code ^= this.getPrincipal().hashCode();
        }

        if (this.getCredentials() != null) {
            code ^= this.getCredentials().hashCode();
        }

        if (this.getDetails() != null) {
            code ^= this.getDetails().hashCode();
        }

        if (this.isAuthenticated()) {
            code ^= -37;
        }

        return code;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }

    public void setDetails(Object details) {
        this.details = details;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString()).append(": ");
        sb.append("Principal: ").append(this.getPrincipal()).append("; ");
        sb.append("Password: [PROTECTED]; ");
        sb.append("Authenticated: ").append(this.isAuthenticated()).append("; ");
        sb.append("Details: ").append(this.getDetails()).append("; ");

        if (this.getAuthorities() != null) {
            sb.append("Granted Authorities: ");

            for (int i = 0; i < this.getAuthorities().length; i++) {
                if (i > 0) {
                    sb.append(", ");
                }

                sb.append(this.getAuthorities()[i].toString());
            }
        } else {
            sb.append("Not granted any authorities");
        }

        return sb.toString();
    }
}
