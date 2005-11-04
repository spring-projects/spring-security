package net.sf.acegisecurity.providers.jaas;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import net.sf.acegisecurity.GrantedAuthority;

import javax.security.auth.login.LoginContext;

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
