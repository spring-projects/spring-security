/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.providers;

import net.sf.acegisecurity.GrantedAuthority;


/**
 * An {@link net.sf.acegisecurity.Authentication} implementation that is
 * designed for use whilst unit testing.
 * 
 * <p>
 * The corresponding authentication provider is  {@link
 * TestingAuthenticationProvider}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class TestingAuthenticationToken extends AbstractAuthenticationToken {
    //~ Instance fields ========================================================

    private Object credentials;
    private Object principal;
    private GrantedAuthority[] authorities;
    private boolean authenticated = false;

    //~ Constructors ===========================================================

    public TestingAuthenticationToken(Object principal, Object credentials,
                                      GrantedAuthority[] authorities) {
        this.principal = principal;
        this.credentials = credentials;
        this.authorities = authorities;
    }

    private TestingAuthenticationToken() {
        super();
    }

    //~ Methods ================================================================

    public void setAuthenticated(boolean isAuthenticated) {
        this.authenticated = isAuthenticated;
    }

    public boolean isAuthenticated() {
        return this.authenticated;
    }

    public GrantedAuthority[] getAuthorities() {
        return this.authorities;
    }

    public Object getCredentials() {
        return this.credentials;
    }

    public Object getPrincipal() {
        return this.principal;
    }
}
