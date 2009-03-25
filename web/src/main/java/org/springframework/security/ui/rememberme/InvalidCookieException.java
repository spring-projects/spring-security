package org.springframework.security.ui.rememberme;

/**
 * Exception thrown by a RememberMeServices implementation to indicate
 * that a submitted cookie is of an invalid format or has expired.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class InvalidCookieException extends RememberMeAuthenticationException {
    public InvalidCookieException(String message) {
        super(message);
    }
}
