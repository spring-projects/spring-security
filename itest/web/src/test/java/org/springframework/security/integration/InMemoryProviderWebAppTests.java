package org.springframework.security.integration;

import static org.testng.Assert.*;

import javax.servlet.http.Cookie;

import net.sourceforge.jwebunit.junit.WebTester;

import org.testng.annotations.Test;

/**
 * @author Luke Taylor
 */
public class InMemoryProviderWebAppTests extends AbstractWebServerIntegrationTests {

    protected String getContextConfigLocations() {
        return "/WEB-INF/http-security.xml /WEB-INF/in-memory-provider.xml";
    }

    @Test
    public void loginFailsWithinvalidPassword() {
        beginAt("secure/index.html");
        login("jimi", "wrongPassword");
        assertTextPresent("Your login attempt was not successful");
    }

    @Test
    public void loginSucceedsWithCorrectPassword() {
        beginAt("secure/index.html");
        login("jimi", "jimispassword");
        assertTextPresent("A Secure Page");
        tester.gotoPage("/logout");
    }

    @Test
    public void basicAuthenticationIsSuccessful() throws Exception {
        tester.getTestContext().setAuthorization("johnc", "johncspassword");
        beginAt("secure/index.html");
        beginAt("secure/index.html");
    }

    /*
     * Checks use of <jsp:include> with parameters in the secured page.
     */
    @Test
    public void savedRequestWithJspIncludeSeesCorrectParams() {
        beginAt("secure/secure1.jsp?x=0");
        login("jimi", "jimispassword");
        // Included JSP has params ?x=1&y=2
        assertTextPresent("Params: x=1, y=2");
        assertTextPresent("xcount=2");
    }

    // SEC-1255
    @Test
    public void redirectToUrlWithSpecialCharsInFilenameWorksOk() throws Exception {
        beginAt("secure/file%3Fwith%3Fspecial%3Fchars.htm?someArg=1");
        login("jimi", "jimispassword");
        assertTextPresent("I'm file?with?special?chars.htm");
    }

    @Test
    public void persistentLoginIsSuccesful() throws Exception {
        beginAt("secure/index.html");
        tester.checkCheckbox("_spring_security_remember_me");
        login("jimi", "jimispassword");
        Cookie rememberMe = getRememberMeCookie();
        assertNotNull(rememberMe);
        tester.closeBrowser();

        tester.getTestContext().addCookie(rememberMe);
        beginAt("secure/index.html");
        assertTextPresent("A Secure Page");
    }
}
