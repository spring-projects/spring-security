package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.Authentication;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
 * Insert comments here...
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public class JAASNameCallbackHandler implements JAASAuthenticationCallbackHandler {

    private Authentication authentication;

    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }

    public void handle(Callback callback) throws IOException, UnsupportedCallbackException {
        if (callback instanceof NameCallback) {
            NameCallback ncb = (NameCallback) callback;
            ncb.setName(authentication.getPrincipal().toString());
        }
    }
}
