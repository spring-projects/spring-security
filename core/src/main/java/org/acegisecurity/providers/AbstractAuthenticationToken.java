/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
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

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString() + ": ");
        sb.append("Username: " + this.getPrincipal() + "; ");
        sb.append("Password: [PROTECTED]; ");
        sb.append("Authenticated: " + this.isAuthenticated() + "; ");

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
