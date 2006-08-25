package org.acegisecurity.ldap.ppolicy;

/**
 * @author Luke
 * @version $Id$
 */
public class OracleIDPasswordPolicyControl extends PasswordPolicyControl {
    public String getID() {
        return "2.16.840.1.113894.1.8.6";
    }
}
