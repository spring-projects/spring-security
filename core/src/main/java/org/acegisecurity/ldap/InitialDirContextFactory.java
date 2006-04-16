package org.acegisecurity.ldap;

import javax.naming.directory.DirContext;

/**
 * Access point for obtaining LDAP contexts.
 *
 * @see org.acegisecurity.ldap.DefaultInitialDirContextFactory
 *
 * @author Luke Taylor
 * @version $Id$
 */
public interface InitialDirContextFactory {

    /**
     * Provides an initial context without specific user information.
     */
    DirContext newInitialDirContext();

    /**
     * Provides an initial context by binding as a specific user.
     */
    DirContext newInitialDirContext(String userDn, String password);

    /**
     * @return The DN of the contexts returned by this factory.
     */
    String getRootDn();
}
