package org.springframework.security.web.authentication.rememberme;

/**
 * Exception thrown by a RememberMeServices implementation to indicate
 * that a submitted cookie is of an invalid format or has expired.
 *
 * @author Luke Taylor
 */
public class InvalidCookieException extends RememberMeAuthenticationException {
    public InvalidCookieException(String message) {
        super(message);
    }
}
