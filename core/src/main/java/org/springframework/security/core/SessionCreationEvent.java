package org.springframework.security.core;

import org.springframework.context.ApplicationEvent;

/**
 * Generic session creation event which indicates that a session (potentially
 * represented by a security context) has begun.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public abstract class SessionCreationEvent extends ApplicationEvent {

    public SessionCreationEvent(Object source) {
        super(source);
    }
}
