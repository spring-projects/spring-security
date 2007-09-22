package org.springframework.security.ldap.ppolicy;

/**
 * @author Luke
 * @version $Id$
 */
public class PasswordInHistoryException extends PasswordPolicyException {

    public PasswordInHistoryException(String msg) {
        super(msg);
    }

    public PasswordInHistoryException(String msg, Throwable t) {
        super(msg, t);
    }
}
