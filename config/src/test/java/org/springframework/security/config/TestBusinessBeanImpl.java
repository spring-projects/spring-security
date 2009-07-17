package org.springframework.security.config;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;

/**
 * @author Luke Taylor
 * @version $Id: TestBusinessBeanImpl.java 3729 2009-06-26 12:44:46Z ltaylor $
 */
public class TestBusinessBeanImpl implements TestBusinessBean, ApplicationListener<ApplicationEvent> {
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

    public void onApplicationEvent(ApplicationEvent event) {
        System.out.println(event);
    }
}
