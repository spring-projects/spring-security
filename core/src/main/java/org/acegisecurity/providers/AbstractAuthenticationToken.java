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

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;

import org.acegisecurity.userdetails.UserDetails;

/**
 * Base class for Authentication objects.
 * <p>
 * Implementations which use this class should be immutable.
 * </p>
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AbstractAuthenticationToken implements Authentication {

    //~ Instance fields
    private GrantedAuthority[] authorities;

    //~ Constructors ===========================================================

    /**
     * Retained for compatibility with subclasses written before the
     * <tt>AbstractAuthenticationToken(GrantedAuthority[])</tt> constructor
     * was introduced.
     *
     * @deprecated in favour of the constructor which takes a GrantedAuthority[]
     * argument. 
     */
    public AbstractAuthenticationToken() {

    }

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the list of <tt>GrantedAuthority</tt>s for the principal
     *                    represented by this authentication object. A null value
     *                    indicates that no authorities have been granted.
     */
    public AbstractAuthenticationToken(GrantedAuthority[] authorities) {
        if(authorities != null) {
            for (int i = 0; i < authorities.length; i++) {
                if(authorities[i] == null) {
                    throw new IllegalArgumentException("Granted authority element " + i
                        + " is null - GrantedAuthority[] cannot contain any null elements");
                }
            }
        }

        this.authorities = authorities;
    }

    //~ Methods ================================================================

    public boolean equals(Object obj) {
        if (obj instanceof AbstractAuthenticationToken) {
            AbstractAuthenticationToken test = (AbstractAuthenticationToken) obj;

            if (!((this.getAuthorities() == null)
                && (test.getAuthorities() == null))) {
                if ((this.getAuthorities() == null)
                    || (test.getAuthorities() == null)) {
                    return false;
                }

                if (this.getAuthorities().length != test.getAuthorities().length) {
                    return false;
                }

                for (int i = 0; i < this.getAuthorities().length; i++) {
                    if (!this.getAuthorities()[i].equals(
                            test.getAuthorities()[i])) {
                        return false;
                    }
                }
            }

            return (this.getPrincipal().equals(test.getPrincipal())
                && this.getCredentials().equals(test.getCredentials())
                && (this.isAuthenticated() == test.isAuthenticated()));
        }

        return false;
    }

    /**
     * Subclasses should override if they wish to provide additional details
     * about the authentication event.
     *
     * @return always <code>null</code>
     */
    public Object getDetails() {
        return null;
    }

    public String getName() {
        if (this.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) this.getPrincipal()).getUsername();
        }

        return this.getPrincipal().toString();
    }

    public GrantedAuthority[] getAuthorities() {
        if(authorities == null) {
            return null;
        }

        GrantedAuthority[] copy = new GrantedAuthority[authorities.length];
        System.arraycopy(authorities, 0, copy, 0, authorities.length);

        return copy;
    }

    public int hashCode() {
        int code = 2305;

        if (this.getAuthorities() != null) {
            for (int i = 0; i < this.getAuthorities().length; i++) {
                code = code * (this.getAuthorities()[i].hashCode() % 7);
            }
        }

        if (this.getPrincipal() != null) {
            code = code * (this.getPrincipal().hashCode() % 7);
        }

        if (this.getCredentials() != null) {
            code = code * (this.getCredentials().hashCode() % 7);
        }

        if (this.isAuthenticated()) {
            code = code * -1;
        }

        return code;
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString()).append(": ");
        sb.append("Username: ").append(this.getPrincipal()).append("; ");
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
