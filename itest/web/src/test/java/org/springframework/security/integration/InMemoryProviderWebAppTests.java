package org.springframework.security.integration;

import net.sourceforge.jwebunit.junit.WebTester;

import org.testng.annotations.Test;

/**
 * @author Luke Taylor
 * @version $Id$
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
    public void maxConcurrentLoginsValueIsRespected() throws Exception {
        System.out.println("Client: ******* First login ******* ");
        beginAt("secure/index.html");
        login("jimi", "jimispassword");
        // Login again
        System.out.println("Client: ******* Second login ******* ");
        WebTester tester2 = new WebTester();
        tester2.getTestContext().setBaseUrl(getBaseUrl());
        tester2.beginAt("secure/index.html");
        // seems to be a bug in checking for form here (it fails)
        //tester2.assertFormPresent();
        tester2.setTextField("j_username", "jimi");
        tester2.setTextField("j_password", "jimispassword");
        // tester2.submit() also fails to detect the form
        tester2.getTestingEngine().submit();
        // Try an use the original
        System.out.println("Client: ******* Retry Original Session ******* ");
        tester.gotoPage("secure/index.html");
        tester.assertTextPresent("This session has been expired");
    }

}
