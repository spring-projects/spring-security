/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.adapters;

import net.sf.acegisecurity.GrantedAuthority;

import java.security.Principal;


/**
 * A {@link Principal} compatible  {@link net.sf.acegisecurity.Authentication}
 * object.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class PrincipalAcegiUserToken extends AbstractAdapterAuthenticationToken
    implements Principal {
    //~ Instance fields ========================================================

    private String password;
    private String username;

    //~ Constructors ===========================================================

    public PrincipalAcegiUserToken(String key, String username,
        String password, GrantedAuthority[] authorities) {
        super(key, authorities);
        this.username = username;
        this.password = password;
    }

    private PrincipalAcegiUserToken() {
        super();
    }

    //~ Methods ================================================================

    public Object getCredentials() {
        return this.password;
    }

    public String getName() {
        return this.username;
    }

    public Object getPrincipal() {
        return this.username;
    }
}
