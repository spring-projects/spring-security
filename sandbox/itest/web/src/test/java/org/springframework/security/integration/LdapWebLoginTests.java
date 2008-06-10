package org.springframework.security.integration;

import org.testng.annotations.*;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapWebLoginTests extends AbstractWebLoginTests {

    protected String getContextConfigLocations() {
        return "/WEB-INF/http-security.xml /WEB-INF/ldap-provider.xml";
    }

    @Test
    public void doSomething() {

    }

}
