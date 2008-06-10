package org.springframework.security.integration;

import org.testng.annotations.Test;

/**
 * 
 * @author Luke Taylor
 * @version $Id$
 */
public abstract class AbstractWebLoginTests extends AbstractWebServerIntegrationTests {

    @Test
    public void loginFailsWithinvalidPassword() {
        beginAt("secure/index.html");
        assertFormPresent();
        setFormElement("j_username", "bob");
        setFormElement("j_password", "wrongpassword");
        submit();
        assertTextPresent("Your login attempt was not successful");
    }

    @Test
    public void loginSucceedsWithCorrectPassword() {
        beginAt("secure/index.html");
        assertFormPresent();
        setFormElement("j_username", "bob");
        setFormElement("j_password", "bobspassword");
        submit();
        assertTextPresent("A Secure Page");
    }
}
