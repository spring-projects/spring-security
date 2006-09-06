package org.acegisecurity.ldap.ppolicy;

import org.acegisecurity.AuthenticationException;

/**
 * @author Luke
 * @version $Id$
 */
public class PasswordPolicyException extends AuthenticationException {
    public PasswordPolicyException(String msg) {
        super(msg);
    }

    public PasswordPolicyException(String msg, Throwable t) {
        super(msg, t);
    }
}
