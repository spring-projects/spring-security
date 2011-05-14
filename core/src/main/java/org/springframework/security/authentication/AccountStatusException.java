package org.springframework.security.authentication;

import org.springframework.security.core.AuthenticationException;

/**
 * Base class for authentication exceptions which are caused by a particular
 * user account status (locked, disabled etc).
 *
 * @author Luke Taylor
 */
public abstract class AccountStatusException extends AuthenticationException {
    public AccountStatusException(String msg) {
        super(msg);
    }

    public AccountStatusException(String msg, Throwable t) {
        super(msg, t);
    }

    @Deprecated
    protected AccountStatusException(String msg, Object extraInformation) {
        super(msg, extraInformation);
    }
}
