package org.springframework.security.config;

/**
 * @author luke
 * @version $Id: TestBusinessBean.java 3541 2009-03-23 04:23:48Z ltaylor $
 */
public interface TestBusinessBean {

    void setInteger(int i);

    int getInteger();

    void setString(String s);

    void doSomething();

    void unprotected();
}
