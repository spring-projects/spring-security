package net.sf.acegisecurity.providers.x509;

import net.sf.acegisecurity.providers.AbstractAuthenticationToken;
import net.sf.acegisecurity.GrantedAuthority;

import java.security.cert.X509Certificate;

/**
 * <code>Authentication</code> implementation for X.509 client-certificate authentication.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class X509AuthenticationToken extends AbstractAuthenticationToken {
    //~ Instance fields ========================================================

    private X509Certificate credentials;
    private Object principal;
    private GrantedAuthority[] authorities;
    private boolean authenticated = false;

    //~ Constructors ===========================================================

    /** Used for an authentication request */
    public X509AuthenticationToken(X509Certificate credentials) {
        this.credentials = credentials;
    }

    public X509AuthenticationToken(Object principal, X509Certificate credentials, GrantedAuthority[] authorities) {
        this.credentials = credentials;
        this.principal = principal;
        this.authorities = authorities;
    }

    //~ Methods ================================================================

    public void setAuthenticated(boolean isAuthenticated) {
        this.authenticated = isAuthenticated;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public GrantedAuthority[] getAuthorities() {
        return authorities;
    }

    public Object getCredentials() {
        return credentials;
    }

    public Object getPrincipal() {
        return principal;
    }
}
