package org.springframework.security.config;

/**
 * @author luke
 */
public interface TestBusinessBean {

    void setInteger(int i);

    int getInteger();

    void setString(String s);

    void doSomething();

    void unprotected();
}
