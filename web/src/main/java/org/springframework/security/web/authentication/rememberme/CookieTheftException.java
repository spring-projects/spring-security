package org.springframework.security.web.authentication.rememberme;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class CookieTheftException extends RememberMeAuthenticationException {
    public CookieTheftException(String message) {
        super(message);
    }
}
