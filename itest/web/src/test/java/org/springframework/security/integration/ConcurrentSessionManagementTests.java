package org.springframework.security.integration;

import net.sourceforge.jwebunit.junit.WebTester;
import org.testng.annotations.Test;

/**
 * @author Luke Taylor
 */
public class ConcurrentSessionManagementTests extends AbstractWebServerIntegrationTests {

    protected String getContextConfigLocations() {
        return "/WEB-INF/http-security-concurrency.xml /WEB-INF/in-memory-provider.xml";
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
        tester2.assertTextPresent("Maximum sessions of 1 for this principal exceeded");

        // Now logout to kill first session
        tester.gotoPage("/logout");


        // Try second session again
        tester2.setTextField("j_username", "jimi");
        tester2.setTextField("j_password", "jimispassword");
        // tester2.submit() also fails to detect the form
        tester2.getTestingEngine().submit();
        tester2.assertTextPresent("A Secure Page");
    }
}
