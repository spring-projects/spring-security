package net.sf.acegisecurity.providers.jaas;

import net.sf.acegisecurity.Authentication;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
 * The JAASAuthenticationCallbackHandler is similar to the javax.security.auth.callback.CallbackHandler interface
 * in that it defines a handle method. The JAASAuthenticationCallbackHandler is only asked to handle one Callback instance at at time
 * rather than an array of all Callbacks, as the javax... CallbackHandler defines.
 * <p/>
 * Before a JAASAuthenticationCallbackHandler is asked to 'handle' any callbacks, it is first passed the Authentication
 * object that the login attempt is for. NOTE: The Authentication object has not been 'authenticated' yet.
 * </p>
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 * @see JAASNameCallbackHandler
 * @see JAASPasswordCallbackHandler
 * @see <a href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/Callback.html">Callback</a>
 * @see <a href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/CallbackHandler.html">CallbackHandler</a>
 */
public interface JAASAuthenticationCallbackHandler {

    /**
     * Called by the JAASAuthenticationProvider before calling the handle method for any Callbacks.
     *
     * @param auth The Authentication object currently being authenticated.
     */
    void setAuthentication(Authentication auth);

    /**
     * Handle the <a href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/Callback.html">Callback</a>.
     * The handle method will be called for every callback instance sent from the LoginContext. Meaning that The handle
     * method may be called multiple times for a given JAASAuthenticationCallbackHandler, after a single call
     * to the {@link #setAuthentication(net.sf.acegisecurity.Authentication) setAuthentication} method.
     *
     * @param callback
     * @throws IOException
     * @throws UnsupportedCallbackException
     */
    void handle(Callback callback) throws IOException, UnsupportedCallbackException;

}
