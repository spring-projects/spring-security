package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.GrantedAuthorityImpl;

import java.security.Principal;

/**
 * Insert comments here...
 * <br>
 * User: raykrueger@users.sourceforge.net<br>
 * Date: Jul 15, 2004<br>
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
