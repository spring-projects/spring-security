package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.Authentication;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
 * The most basic Callbacks to be handled when using a LoginContext from JAAS, are the NameCallback and PasswordCallback.
 * The acegi security framework provides the JAASPasswordCallbackHandler specifically tailored to handling the PasswordCallback.
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 * @see <a href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/Callback.html">Callback</a>
 * @see <a href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/PasswordCallback.html">PasswordCallback</a>
 */
public class JAASPasswordCallbackHandler implements JAASAuthenticationCallbackHandler {

    private Authentication auth;

    public void setAuthentication(Authentication auth) {
        this.auth = auth;
    }

    /**
     * If the callback passed to the 'handle' method is an instance of PasswordCallback, the JAASPasswordCallbackHandler will call,
     * callback.setPassword(authentication.getCredentials().toString()). Where 'authentication' is the {@link Authentication}
     * object used in the {@link JAASAuthenticationCallbackHandler#setAuthentication(net.sf.acegisecurity.Authentication) setAuthentication} method.
     *
     * @param callback
     * @throws IOException                  
     * @throws UnsupportedCallbackException
     */
    public void handle(Callback callback) throws IOException, UnsupportedCallbackException {
        if (callback instanceof PasswordCallback) {
            PasswordCallback pc = (PasswordCallback) callback;
            pc.setPassword(auth.getCredentials().toString().toCharArray());
        }
    }
}
