package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.GrantedAuthorityImpl;

import java.security.Principal;

/**
 * Extends GrantedAuthorityImpl to hold the principal that an AuthorityGranter justified as a reason to grant this Authority.
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 * @see AuthorityGranter
 */
public class JaasGrantedAuthority extends GrantedAuthorityImpl {

    private Principal principal;

    public JaasGrantedAuthority(String role, Principal principal) {
        super(role);
        this.principal = principal;
    }

    public Principal getPrincipal() {
        return principal;
    }
}
