package org.springframework.security.core.session;

import org.springframework.context.ApplicationEvent;

/**
 * Generic session creation event which indicates that a session (potentially
 * represented by a security context) has begun.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public abstract class SessionCreationEvent extends ApplicationEvent {

    public SessionCreationEvent(Object source) {
        super(source);
    }
}
