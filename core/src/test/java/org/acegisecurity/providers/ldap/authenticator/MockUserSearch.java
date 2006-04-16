package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.ldap.LdapUserInfo;
import org.acegisecurity.ldap.LdapUserSearch;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class MockUserSearch implements LdapUserSearch {
    LdapUserInfo user;

    public MockUserSearch(LdapUserInfo user) {
        this.user = user;
    }

    public LdapUserInfo searchForUser(String username) {
        return user;
    }
}
