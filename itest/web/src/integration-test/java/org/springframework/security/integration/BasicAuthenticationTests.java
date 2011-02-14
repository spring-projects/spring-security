package org.springframework.security.integration;

import org.testng.annotations.Test;

public class BasicAuthenticationTests extends AbstractWebServerIntegrationTests {

    @Override
    protected String getContextConfigLocations() {
        return "/WEB-INF/http-security-basic.xml /WEB-INF/in-memory-provider.xml";
    }

    @Test
    public void basicAuthenticationIsSuccessful() throws Exception {
        tester.setIgnoreFailingStatusCodes(true);
        beginAt("secure/index.html");
        // Ignore the 401
        tester.setIgnoreFailingStatusCodes(false);
        tester.assertHeaderEquals("WWW-Authenticate", "Basic realm=\"Spring Security Application\"");
        tester.getTestContext().setAuthorization("johnc", "johncspassword");
        beginAt("secure/index.html");
    }

}
