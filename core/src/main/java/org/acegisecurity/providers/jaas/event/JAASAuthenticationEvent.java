package net.sf.acegisecurity.providers.jaas.event;

import net.sf.acegisecurity.Authentication;
import org.springframework.context.ApplicationEvent;

/**
 * Insert comments here...
 * <br>
 *
 * @author Ray Krueger
 * @version $Id$
 */
public abstract class JAASAuthenticationEvent extends ApplicationEvent {

    public JAASAuthenticationEvent(Authentication auth) {
        super(auth);
    }

    public Authentication getAuthentication() {
        return (Authentication) source;
    }
}
