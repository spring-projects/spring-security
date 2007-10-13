package org.springframework.security.config;

/**
 * @author luke
 * @version $Id$
 */
public class TestBusinessBeanImpl implements TestBusinessBean {
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
}
