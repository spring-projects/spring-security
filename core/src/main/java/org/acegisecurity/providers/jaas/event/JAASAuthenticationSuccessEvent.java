package net.sf.acegisecurity.providers.jaas.event;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.providers.jaas.event.JAASAuthenticationEvent;

/**
 * Insert comments here...
 * <br>
 * User: raykrueger@users.sourceforge.net<br>
 * Date: Jul 15, 2004<br>
 */
public class JAASAuthenticationSuccessEvent extends JAASAuthenticationEvent {

    public JAASAuthenticationSuccessEvent(Authentication auth) {
        super(auth);
    }

}
