package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.Authentication;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
 * Insert comments here...
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public class TestCallbackHandler implements JaasAuthenticationCallbackHandler {

    Authentication auth;

    public void setAuthentication(Authentication auth) {
        this.auth = auth;
    }

    public void handle(Callback callback) throws IOException, UnsupportedCallbackException {
        if (callback instanceof TextInputCallback) {
            TextInputCallback tic = (TextInputCallback) callback;
            tic.setText(auth.getPrincipal().toString());
        }
    }
}
