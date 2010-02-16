package org.springframework.security.config;

import org.springframework.context.ApplicationListener;
import org.springframework.security.core.session.SessionCreationEvent;

/**
 * @author Luke Taylor
 */
public class TestBusinessBeanImpl implements TestBusinessBean, ApplicationListener<SessionCreationEvent> {
    public void setInteger(int i) {
    }

    public int getInteger() {
        return 1314;
    }

    public void setString(String s) {
    }

    public String getString() {
        return "A string.";
    }

    public void doSomething() {
    }

    public void unprotected() {
    }

    public void onApplicationEvent(SessionCreationEvent event) {
        System.out.println(event);
    }
}
