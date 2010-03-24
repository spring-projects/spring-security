package org.springframework.security.integration;

import static org.testng.Assert.*;

import org.testng.annotations.Test;

/**
 *
 * @author Luke Taylor
 */
public final class JspTaglibTests extends AbstractWebServerIntegrationTests {

    @Override
    protected String getContextConfigLocations() {
        return "/WEB-INF/http-security.xml /WEB-INF/in-memory-provider.xml";
    }

    @Test
    public void authenticationTagEscapingWorksCorrectly() {
        beginAt("secure/authenticationTagTestPage.jsp");
        login("theescapist<>&.", "theescapistspassword");
        String response = tester.getServerResponse();
        assertTrue(response.contains("This is the unescaped authentication name: theescapist<>&."));
        assertTrue(response.contains("This is the unescaped principal.username: theescapist<>&."));
        assertTrue(response.contains("This is the authentication name: theescapist&lt;&gt;&amp;&#46;"));
        assertTrue(response.contains("This is the principal.username: theescapist&lt;&gt;&amp;&#46;"));
    }

    @Test
    public void authorizationTagEvaluatesExpressionCorrectlyAndWritesValueToVariable() {
        beginAt("secure/authorizationTagTestPage.jsp");
        login("bessie", "bessiespassword");
        String response = tester.getServerResponse();
        assertTrue(response.contains("Users can see this and 'allowed' variable is true."));
        assertFalse(response.contains("Role X users (nobody) can see this."));
        assertTrue(response.contains("Role X expression evaluates to false"));
    }

}
