package net.sf.acegisecurity.providers.jaas.event;

import net.sf.acegisecurity.Authentication;
import org.springframework.context.ApplicationEvent;

/**
 * Parent class for events fired by the {@link net.sf.acegisecurity.providers.jaas.JAASAuthenticationProvider JAASAuthenticationProvider}.
 *
 * @author Ray Krueger
 * @version $Id$
 */
public abstract class JAASAuthenticationEvent extends ApplicationEvent {

    /**
     * The Authentication object is stored as the ApplicationEvent 'source'.
     *
     * @param auth
     */
    public JAASAuthenticationEvent(Authentication auth) {
        super(auth);
    }

    /**
     * Pre-casted method that returns the 'source' of the event.
     *
     * @return
     */
    public Authentication getAuthentication() {
        return (Authentication) source;
    }
}
