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
 * designed for simple presentation of a username and password.
 * 
 * <p>
 * The <code>principal</code> and <code>credentials</code> should be set with
 * an <code>Object</code> that provides the respective property via its
 * <code>Object.toString()</code> method. The simplest such
 * <code>Object</code> to use is <code>String</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UsernamePasswordAuthenticationToken
    extends AbstractAuthenticationToken {
    //~ Instance fields ========================================================

    private Object credentials;
    private Object principal;
    private GrantedAuthority[] authorities;
    private boolean authenticated = false;

    //~ Constructors ===========================================================

    public UsernamePasswordAuthenticationToken(Object principal,
                                               Object credentials) {
        this.principal = principal;
        this.credentials = credentials;
    }

    public UsernamePasswordAuthenticationToken(Object principal,
                                               Object credentials,
                                               GrantedAuthority[] authorities) {
        this.principal = principal;
        this.credentials = credentials;
        this.authorities = authorities;
    }

    private UsernamePasswordAuthenticationToken() {
        super();
    }

    //~ Methods ================================================================

    public void setAuthenticated(boolean isAuthenticated) {
        this.authenticated = isAuthenticated;
    }

    public boolean isAuthenticated() {
        return this.authenticated;
    }

    public void setAuthorities(GrantedAuthority[] authorities) {
        this.authorities = authorities;
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
