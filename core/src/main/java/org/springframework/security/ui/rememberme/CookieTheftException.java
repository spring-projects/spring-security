package org.springframework.security.ui.rememberme;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class CookieTheftException extends RememberMeAuthenticationException {
    public CookieTheftException(String message) {
        super(message);
    }
}
