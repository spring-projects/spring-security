package org.springframework.security.web.authentication.preauth;

import org.springframework.security.core.AuthenticationException;

public class PreAuthenticatedCredentialsNotFoundException extends AuthenticationException {

    public PreAuthenticatedCredentialsNotFoundException(String msg) {
        super(msg);
    }

    /**
     *
     * @param message The message for the Exception
     * @param cause The Exception that caused this Exception.
     */
    public PreAuthenticatedCredentialsNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
