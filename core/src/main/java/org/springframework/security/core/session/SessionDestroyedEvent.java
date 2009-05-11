package org.springframework.security.core.session;

import org.springframework.context.ApplicationEvent;
import org.springframework.security.core.context.SecurityContext;

/**
 * Generic "session termination" event which indicates that a session (potentially
 * represented by a security context) has ended.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public abstract class SessionDestroyedEvent extends ApplicationEvent {

    public SessionDestroyedEvent(Object source) {
        super(source);
    }

    /**
     * Provides the <tt>SecurityContext</tt> under which the session was running.
     *
     * @return the <tt>SecurityContext</tt> associated with the session, or null if there is no context.
     */
    public abstract SecurityContext getSecurityContext();

    /**
     * The identifier associated with the destroyed session.
     * @return
     */
    public abstract String getId();
}
