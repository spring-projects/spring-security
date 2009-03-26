package org.springframework.security.web.authentication;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

public class SavedRequestAwareAuthenticationSuccessHandlerTests {

    @Test
    public void defaultUrlMuststartWithSlashOrHttpScheme() {
        SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();

        handler.setDefaultTargetUrl("/acceptableRelativeUrl");
        handler.setDefaultTargetUrl("http://some.site.org/index.html");
        handler.setDefaultTargetUrl("https://some.site.org/index.html");

        try {
            handler.setDefaultTargetUrl("missingSlash");
            fail("Shouldn't accept default target without leading slash");
        } catch (IllegalArgumentException expected) {}
    }
}
