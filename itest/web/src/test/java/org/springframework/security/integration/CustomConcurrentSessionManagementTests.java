package org.springframework.security.integration;

import net.sourceforge.jwebunit.junit.WebTester;

import org.junit.Assert;
import org.testng.annotations.Test;

/**
 * @author Luke Taylor
 */
public class CustomConcurrentSessionManagementTests extends AbstractWebServerIntegrationTests {

    protected String getContextConfigLocations() {
        return "/WEB-INF/http-security-custom-concurrency.xml /WEB-INF/in-memory-provider.xml";
    }

    @Test
    public void maxConcurrentLoginsValueIsRespected() throws Exception {
        beginAt("secure/index.html");
        login("jimi", "jimispassword");
        // Login again
        System.out.println("Client: ******* Second login ******* ");
        WebTester tester2 = new WebTester();
        tester2.getTestContext().setBaseUrl(getBaseUrl());
        tester2.beginAt("secure/index.html");
        tester2.setTextField("j_username", "jimi");
        tester2.setTextField("j_password", "jimispassword");
        tester2.setIgnoreFailingStatusCodes(true);
        tester2.submit();
        Assert.assertTrue(tester2.getServerResponse().contains("Maximum sessions of 1 for this principal exceeded"));
    }

}
