package org.springframework.security.ui.openid;

import junit.framework.TestCase;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.ui.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.ui.openid.consumers.MockOpenIDConsumer;
import org.springframework.security.util.MockFilterChain;

import javax.servlet.http.HttpServletRequest;

public class OpenIDAuthenticationProcessingFilterTests extends TestCase {

    OpenIDAuthenticationProcessingFilter filter;
    private static final String REDIRECT_URL = "http://www.example.com/redirect";
    private static final String CLAIMED_IDENTITY_URL = "http://www.example.com/identity";
    private static final String REQUEST_PATH = "/j_spring_openid_security_check";
    private static final String FILTER_PROCESS_URL = "http://localhost:80" + REQUEST_PATH;
    private static final String DEFAULT_TARGET_URL = FILTER_PROCESS_URL;

    protected void setUp() throws Exception {
        filter = new OpenIDAuthenticationProcessingFilter();
        filter.setConsumer(new MockOpenIDConsumer(REDIRECT_URL));
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        filter.setSuccessHandler(new SavedRequestAwareAuthenticationSuccessHandler());
        successHandler.setDefaultTargetUrl(DEFAULT_TARGET_URL);
        filter.setAuthenticationManager(new MockAuthenticationManager());
        filter.afterPropertiesSet();
    }

    public void testFilterOperation() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", REQUEST_PATH);
        MockHttpServletResponse response = new MockHttpServletResponse();

        req.setParameter("j_username", CLAIMED_IDENTITY_URL);
        req.setRemoteHost("www.example.com");

        filter.setConsumer(new MockOpenIDConsumer() {
            public String beginConsumption(HttpServletRequest req, String claimedIdentity, String returnToUrl, String realm) throws OpenIDConsumerException {
                assertEquals(CLAIMED_IDENTITY_URL, claimedIdentity);
                assertEquals(DEFAULT_TARGET_URL, returnToUrl);
                assertEquals("http://localhost:80/", realm);
                return REDIRECT_URL;
            }
        });

        filter.doFilter(req, response, new MockFilterChain(false));
        assertEquals(REDIRECT_URL, response.getRedirectedUrl());
    }


}
