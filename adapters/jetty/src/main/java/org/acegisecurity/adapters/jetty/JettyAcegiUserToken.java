/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.adapters.jetty;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.adapters.AbstractAdapterAuthenticationToken;

import org.mortbay.http.UserPrincipal;


/**
 * A Jetty compatible {@link net.sf.acegisecurity.Authentication} object.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JettyAcegiUserToken extends AbstractAdapterAuthenticationToken
    implements UserPrincipal {
    //~ Instance fields ========================================================

    private String password;
    private String username;

    //~ Constructors ===========================================================

    public JettyAcegiUserToken(String key, String username, String password,
        GrantedAuthority[] authorities) {
        super(key, authorities);
        this.username = username;
        this.password = password;
    }

    private JettyAcegiUserToken() {
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
