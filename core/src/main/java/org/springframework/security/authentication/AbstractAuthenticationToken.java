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

import java.security.Principal;
import java.util.Collections;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


/**
 * Base class for <code>Authentication</code> objects.
 * <p>
 * Implementations which use this class should be immutable.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AbstractAuthenticationToken implements Authentication {
    //~ Instance fields ================================================================================================

    private Object details;
    private List<GrantedAuthority> authorities;
    private boolean authenticated = false;

    //~ Constructors ===================================================================================================

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
    public AbstractAuthenticationToken(List<GrantedAuthority> authorities) {
        if (authorities != null) {
            for (int i = 0; i < authorities.size(); i++) {
                if(authorities.get(i) == null) {
                    throw new IllegalArgumentException("Granted authority element " + i
                            + " is null - GrantedAuthority[] cannot contain any null elements");
                }
            }
            this.authorities = Collections.unmodifiableList(authorities);
        }
    }

    //~ Methods ========================================================================================================

    public boolean equals(Object obj) {
        if (!(obj instanceof AbstractAuthenticationToken)) {
            return false;
        }

        AbstractAuthenticationToken test = (AbstractAuthenticationToken) obj;

        if (!(authorities == null && test.authorities == null)) {
            // Not both null
            if (authorities == null || test.authorities == null) {
                return false;
            }
            if(!authorities.equals(test.authorities)) {
                return false;
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

        if (this.getPrincipal() == null && test.getPrincipal() != null) {
            return false;
        }

        if (this.getPrincipal() != null && !this.getPrincipal().equals(test.getPrincipal())) {
            return false;
        }

        return this.isAuthenticated() == test.isAuthenticated();
    }

    public List<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public Object getDetails() {
        return details;
    }

    public String getName() {
        if (this.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) this.getPrincipal()).getUsername();
        }

        if (getPrincipal() instanceof Principal) {
            return ((Principal)getPrincipal()).getName();
        }

        return (this.getPrincipal() == null) ? "" : this.getPrincipal().toString();
    }

    public int hashCode() {
        int code = 31;

        if (authorities != null) {
            for (GrantedAuthority authority : authorities) {
                code ^= authority.hashCode();
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

        if (authorities != null) {
            sb.append("Granted Authorities: ");

            int i = 0;
            for (GrantedAuthority authority: authorities) {
                if (i++ > 0) {
                    sb.append(", ");
                }

                sb.append(authority);
            }
        } else {
            sb.append("Not granted any authorities");
        }

        return sb.toString();
    }
}
