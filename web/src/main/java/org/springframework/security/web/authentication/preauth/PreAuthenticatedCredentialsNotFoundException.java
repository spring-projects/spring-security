package org.springframework.security.web.authentication.preauth;

import org.springframework.security.core.AuthenticationException;

public class PreAuthenticatedCredentialsNotFoundException extends AuthenticationException {

    public PreAuthenticatedCredentialsNotFoundException(String msg) {
        super(msg);
    }

}
