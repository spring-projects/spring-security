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
public class TestCallbackHandler implements JAASAuthenticationCallbackHandler {

    Authentication auth;

    public void setAuthentication(Authentication auth) {
        this.auth = auth;
    }

    public void handle(Callback callback) throws IOException, UnsupportedCallbackException {

        if (auth == null) throw new RuntimeException("TEST FAILURE: setAuthentication was never called");

        if (callback instanceof TextInputCallback) {
            TextInputCallback tic = (TextInputCallback) callback;
            tic.setText(getClass().getName());
        }
    }
}
