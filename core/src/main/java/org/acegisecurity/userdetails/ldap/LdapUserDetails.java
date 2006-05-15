package org.acegisecurity.userdetails.ldap;

import org.acegisecurity.userdetails.UserDetails;

import javax.naming.directory.Attributes;
import javax.naming.ldap.Control;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public interface LdapUserDetails extends UserDetails {
    /**
     * @return the DN of the entry for this user's account.
     */
    String getDn();

    /**
     * @return the attributes for the user's entry in the directory (or a subset of them,
     * depending on what was retrieved).
     */
    Attributes getAttributes();

    /**
     * Returns any LDAP response controls (as part of a user authentication process, for example).
     *
     * @return an array of LDAP Control instances, never null
     */
    Control[] getControls();
}
