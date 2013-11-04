package org.springframework.security.web.authentication.rememberme;

import org.springframework.security.core.AuthenticationException;

/**
 * This exception is thrown when an {@link org.springframework.security.core.Authentication} exception occurs while
 * using the remember-me authentication.
 *
 * @author Luke Taylor
 */
public class RememberMeAuthenticationException extends AuthenticationException {

    //~ Constructors ===================================================================================================

    /**
     * Constructs a {@code RememberMeAuthenticationException} with the specified message and root cause.
     *
     * @param msg the detail message
     * @param t the root cause
     */
    public RememberMeAuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }

    /**
     * Constructs an {@code RememberMeAuthenticationException} with the specified message and no root cause.
     *
     * @param msg the detail message
     */
    public RememberMeAuthenticationException(String msg) {
        super(msg);
    }
}
