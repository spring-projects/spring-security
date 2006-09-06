package org.acegisecurity.ldap.ppolicy;

/**
 * @author Luke
 * @version $Id$
 */
public class PasswordExpiredException extends PasswordPolicyException {
    public PasswordExpiredException(String msg) {
        super(msg);
    }

    public PasswordExpiredException(String msg, Throwable t) {
        super(msg, t);
    }
}
