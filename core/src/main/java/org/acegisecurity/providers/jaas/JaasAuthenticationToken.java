package org.acegisecurity.providers.jaas;

import javax.security.auth.login.LoginContext;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

/**
 * UsernamePasswordAuthenticationToken extension to carry the Jaas LoginContext that the user was logged into
 * @author Ray Krueger
 */
public class JaasAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private transient LoginContext loginContext = null;

    public JaasAuthenticationToken(Object principal, Object credentials, LoginContext loginContext) {
        super(principal, credentials);
        this.loginContext = loginContext;
    }

    public JaasAuthenticationToken(Object principal, Object credentials, GrantedAuthority[] authorities, LoginContext loginContext) {
        super(principal, credentials, authorities);
        this.loginContext = loginContext;
    }

    public LoginContext getLoginContext() {
        return loginContext;
    }
}
