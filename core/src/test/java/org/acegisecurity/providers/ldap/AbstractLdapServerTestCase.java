package org.acegisecurity.providers.ldap;

import junit.framework.TestCase;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AbstractLdapServerTestCase extends TestCase {
    protected static final String ROOT_DN = "dc=acegisecurity,dc=org";
    //protected static final String PROVIDER_URL = "ldap://monkeymachine:389/"+ROOT_DN;
    protected static final String PROVIDER_URL = "ldap://localhost:10389/" + ROOT_DN;
    protected static final String MANAGER_USER = "cn=manager," + ROOT_DN;
    protected static final String MANAGER_PASSWORD = "acegisecurity";

    protected static final LdapTestServer server = new LdapTestServer();

    protected AbstractLdapServerTestCase() {
    }

    protected AbstractLdapServerTestCase(String string) {
        super(string);
    }
}
