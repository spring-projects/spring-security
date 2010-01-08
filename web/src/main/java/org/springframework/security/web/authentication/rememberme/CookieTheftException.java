package org.springframework.security.web.authentication.rememberme;

/**
 * @author Luke Taylor
 */
public class CookieTheftException extends RememberMeAuthenticationException {
    public CookieTheftException(String message) {
        super(message);
    }
}
