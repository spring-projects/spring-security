/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.providers.dao.memory;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;

import java.util.HashSet;
import java.util.Set;


/**
 * Used by {@link InMemoryDaoImpl} to temporarily store the attributes
 * associated with a user.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UserAttributeDefinition {
    //~ Instance fields ========================================================

    private Set authorities = new HashSet();
    private String password;
    private boolean enabled = true;

    //~ Constructors ===========================================================

    public UserAttributeDefinition() {
        super();
    }

    //~ Methods ================================================================

    public GrantedAuthority[] getAuthorities() {
        GrantedAuthority[] toReturn = {new GrantedAuthorityImpl("demo")};

        return (GrantedAuthority[]) this.authorities.toArray(toReturn);
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

    public boolean isValid() {
        if ((this.password != null) && (authorities.size() > 0)) {
            return true;
        } else {
            return false;
        }
    }

    public void addAuthority(GrantedAuthority newAuthority) {
        this.authorities.add(newAuthority);
    }
}
