package net.sf.acegisecurity.providers.jaas.event;

import net.sf.acegisecurity.Authentication;

/**
 * Insert comments here...
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
