package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.Authentication;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
 * Insert comments here...
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public interface JAASAuthenticationCallbackHandler {
    void setAuthentication(Authentication auth);

    void handle(Callback callback) throws IOException, UnsupportedCallbackException;

}
