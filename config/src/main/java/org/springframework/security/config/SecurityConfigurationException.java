package org.springframework.security.config;

import org.springframework.security.core.SpringSecurityException;


/**
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityConfigurationException extends SpringSecurityException {
    public SecurityConfigurationException(String s) {
        super(s);
    }

    public SecurityConfigurationException(String s, Throwable throwable) {
        super(s, throwable);
    }
}
