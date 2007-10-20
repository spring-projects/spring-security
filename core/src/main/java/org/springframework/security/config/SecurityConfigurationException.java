package org.springframework.security.config;


/**
 * @author Luke Taylor
 * @version $Id$
 */
public class SecurityConfigurationException extends RuntimeException {
    public SecurityConfigurationException(String s) {
        super(s);
    }

    public SecurityConfigurationException(String s, Throwable throwable) {
        super(s, throwable);
    }
}
