package org.springframework.security;

/**
 * Base class for authentication exceptions which are caused by a particular
 * user account status (locked, disabled etc).
 *
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AccountStatusException extends AuthenticationException {
    public AccountStatusException(String msg) {
        super(msg);
    }

    public AccountStatusException(String msg, Throwable t) {
        super(msg, t);
    }
}
