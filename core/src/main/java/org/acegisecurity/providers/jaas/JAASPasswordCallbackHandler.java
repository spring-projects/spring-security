package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.Authentication;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
 * Insert comments here...
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public class JAASPasswordCallbackHandler implements JAASAuthenticationCallbackHandler {

    private Authentication auth;

    public void setAuthentication(Authentication auth) {
        this.auth = auth;
    }

    public void handle(Callback callback) throws IOException, UnsupportedCallbackException {
        if (callback instanceof PasswordCallback) {
            PasswordCallback pc = (PasswordCallback) callback;
            pc.setPassword(auth.getCredentials().toString().toCharArray());
        }
    }
}
