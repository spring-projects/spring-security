package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.providers.ldap.LdapUserDetails;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class MockUserSearch implements LdapUserSearch {
    LdapUserDetails user;

    public MockUserSearch(LdapUserDetails user) {
        this.user = user;
    }

    public LdapUserDetails searchForUser(String username) {
        return user;
    }
}
