package org.springframework.security;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEvent;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class MockApplicationEventPublisher implements ApplicationEventPublisher {
    private Boolean expectedEvent;
    private ApplicationEvent lastEvent;

    public MockApplicationEventPublisher() {
    }

    public MockApplicationEventPublisher(boolean expectedEvent) {
        this.expectedEvent = Boolean.valueOf(expectedEvent);
    }

    public void publishEvent(ApplicationEvent event) {
        if (expectedEvent != null && !expectedEvent.booleanValue()) {
            throw new IllegalStateException("The ApplicationEventPublisher did not expect to receive this event");
        }

        lastEvent = event;
    }

    public ApplicationEvent getLastEvent() {
        return lastEvent;
    }
}
