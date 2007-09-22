package org.springframework.security.ldap.ppolicy;

/**
 * @author Luke
 * @version $Id$
 */
public class AccountLockedException extends PasswordPolicyException {
    public AccountLockedException(String msg) {
        super(msg);
    }

    public AccountLockedException(String msg, Throwable t) {
        super(msg, t);
    }
}
