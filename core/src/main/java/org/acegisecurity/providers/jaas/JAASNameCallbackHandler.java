package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.Authentication;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
 * The most basic Callbacks to be handled when using a LoginContext from JAAS, are the NameCallback and PasswordCallback.
 * The acegi security framework provides the JAASNameCallbackHandler specifically tailored to handling the NameCallback.
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 * @see <a href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/Callback.html">Callback</a>
 * @see <a href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/NameCallback.html">NameCallback</a>
 */
public class JAASNameCallbackHandler implements JAASAuthenticationCallbackHandler {

    private Authentication authentication;

    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }

    /**
     * If the callback passed to the 'handle' method is an instance of NameCallback, the JAASNameCallbackHandler will call,
     * callback.setName(authentication.getPrincipal().toString()). Where 'authentication' is the {@link Authentication}
     * object used in the {@link #setAuthentication(net.sf.acegisecurity.Authentication) setAuthentication} method.
     * 
     * @param callback
     * @throws IOException
     * @throws UnsupportedCallbackException
     */
    public void handle(Callback callback) throws IOException, UnsupportedCallbackException {
        if (callback instanceof NameCallback) {
            NameCallback ncb = (NameCallback) callback;
            ncb.setName(authentication.getPrincipal().toString());
        }
    }
}
