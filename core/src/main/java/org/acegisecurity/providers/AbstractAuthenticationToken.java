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

package net.sf.acegisecurity.providers;

import net.sf.acegisecurity.Authentication;


/**
 * Provides a <code>String</code> representation of the Authentication token.
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AbstractAuthenticationToken implements Authentication {
    //~ Methods ================================================================

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
        return this.getPrincipal().toString();
    }

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

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString() + ": ");
        sb.append("Username: " + this.getPrincipal() + "; ");
        sb.append("Password: [PROTECTED]; ");
        sb.append("Authenticated: " + this.isAuthenticated() + "; ");
        sb.append("Details: " + this.getDetails() + "; ");

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
