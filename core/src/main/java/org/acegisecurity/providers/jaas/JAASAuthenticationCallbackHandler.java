package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.Authentication;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
 * Insert comments here...
 * <br>
 * User: raykrueger@users.sourceforge.net<br>
 * Date: Jul 15, 2004<br>
 */
public interface JAASAuthenticationCallbackHandler {
    void setAuthentication(Authentication auth);
    void handle(Callback callback) throws IOException, UnsupportedCallbackException;

}
