/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

/**
 * Basic concrete implementation of a {@link GrantedAuthority}.
 * 
 * <p>
 * Stores a <code>String</code> representation of an authority granted to  the
 * {@link Authentication} object.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class GrantedAuthorityImpl implements GrantedAuthority {
    //~ Instance fields ========================================================

    private String role;

    //~ Constructors ===========================================================

    public GrantedAuthorityImpl(String role) {
        super();
        this.role = role;
    }

    private GrantedAuthorityImpl() {
        super();
    }

    //~ Methods ================================================================

    public String getAuthority() {
        return this.role;
    }

    public boolean equals(Object obj) {
        if (obj instanceof String) {
            return obj.equals(this.role);
        }

        if (obj instanceof GrantedAuthority) {
            GrantedAuthority attr = (GrantedAuthority) obj;

            return this.role.equals(attr.getAuthority());
        }

        return false;
    }

    public int hashCode() {
        return this.role.hashCode();
    }

    public String toString() {
        return this.role;
    }
}
