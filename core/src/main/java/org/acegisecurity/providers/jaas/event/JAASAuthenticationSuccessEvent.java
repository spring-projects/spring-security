package net.sf.acegisecurity.providers.jaas.event;

import net.sf.acegisecurity.Authentication;

/**
 * Fired by the {@link net.sf.acegisecurity.providers.jaas.JAASAuthenticationProvider JAASAuthenticationProvider} after
 * successfully logging the user into the LoginContext, handling all callbacks, and calling all AuthorityGranters.
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public class JAASAuthenticationSuccessEvent extends JAASAuthenticationEvent {

    public JAASAuthenticationSuccessEvent(Authentication auth) {
        super(auth);
    }

}
