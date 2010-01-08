package org.springframework.security.integration;

import org.testng.annotations.*;

/**
 * @author Luke Taylor
 */
public class LdapWebAppTests extends AbstractWebServerIntegrationTests {

    protected String getContextConfigLocations() {
        return "/WEB-INF/http-security.xml /WEB-INF/ldap-provider.xml";
    }

    @Test
    public void doSomething() {

    }

}
