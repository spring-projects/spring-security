package org.springframework.security.config;

import org.springframework.core.NestedRuntimeException;

/**
 * @author Luke Taylor
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityConfigurationException extends NestedRuntimeException {
    public SecurityConfigurationException(String s) {
        super(s);
    }

    public SecurityConfigurationException(String s, Throwable throwable) {
        super(s, throwable);
    }
}
