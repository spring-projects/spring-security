package org.springframework.security.ui.rememberme;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class InvalidCookieException extends RememberMeAuthenticationException {
    public InvalidCookieException(String message) {
        super(message);
    }
}
