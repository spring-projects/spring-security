package org.springframework.security;

import java.util.*;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.access.event.AbstractAuthorizationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;

/**
 * ApplicationListener which collects events for use in test assertions
 *
 * @author Luke Taylor
 * @since 3.1
 */
public class CollectingAppListener implements ApplicationListener {
    Set<ApplicationEvent> events = new HashSet<ApplicationEvent>();
    Set<AbstractAuthenticationEvent> authenticationEvents = new HashSet<AbstractAuthenticationEvent>();
    Set<AbstractAuthenticationFailureEvent> authenticationFailureEvents = new HashSet<AbstractAuthenticationFailureEvent>();
    Set<AbstractAuthorizationEvent> authorizationEvents = new HashSet<AbstractAuthorizationEvent>();

    public void onApplicationEvent(ApplicationEvent event) {
        if (event instanceof AbstractAuthenticationEvent) {
            events.add(event);
            authenticationEvents.add((AbstractAuthenticationEvent) event);
        }
        if (event instanceof AbstractAuthenticationFailureEvent) {
            events.add(event);
            authenticationFailureEvents.add((AbstractAuthenticationFailureEvent) event);
        }
        if (event instanceof AbstractAuthorizationEvent) {
            events.add(event);
            authorizationEvents.add((AbstractAuthorizationEvent) event);
        }
    }

    public Set<ApplicationEvent> getEvents() {
        return events;
    }

    public Set<AbstractAuthenticationEvent> getAuthenticationEvents() {
        return authenticationEvents;
    }

    public Set<AbstractAuthenticationFailureEvent> getAuthenticationFailureEvents() {
        return authenticationFailureEvents;
    }

    public Set<AbstractAuthorizationEvent> getAuthorizationEvents() {
        return authorizationEvents;
    }
}
