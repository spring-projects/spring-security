package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.GrantedAuthorityImpl;

import java.security.Principal;

/**
 * Insert comments here...
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public class JAASGrantedAuthority extends GrantedAuthorityImpl {

    Principal principal;

    public JAASGrantedAuthority(String role, Principal principal) {
        super(role);
        this.principal = principal;
    }

    public Principal getPrincipal() {
        return principal;
    }
}
