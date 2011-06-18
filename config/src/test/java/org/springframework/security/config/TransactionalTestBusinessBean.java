package org.springframework.security.config;

import org.springframework.transaction.annotation.Transactional;

/**
 * @author Luke Taylor
 */
public class TransactionalTestBusinessBean implements TestBusinessBean {
    public void setInteger(int i) {
    }

    public int getInteger() {
        return 0;
    }

    public void setString(String s) {
    }

    @Transactional
    public void doSomething() {
    }

    public void unprotected() {
    }
}
