package net.sf.acegisecurity.providers.jaas.event;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.providers.jaas.event.JAASAuthenticationEvent;

/**
 * Insert comments here...
 * <br>
 * User: raykrueger@users.sourceforge.net<br>
 * Date: Jul 15, 2004<br>
 */
public class JAASAuthenticationFailedEvent extends JAASAuthenticationEvent {

    private Exception exception;

    public JAASAuthenticationFailedEvent(Authentication auth, Exception exception) {
        super(auth);
        this.exception = exception;
    }

    public Exception getException() {
        return exception;
    }

}
