package org.springframework.security.ldap.ppolicy;

/**
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public interface PasswordPolicyData {
    int getTimeBeforeExpiration();

    int getGraceLoginsRemaining();
}
