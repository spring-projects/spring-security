package org.springframework.security.openid;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

public class OpenIDAuthenticationFilterTests {

    OpenIDAuthenticationFilter filter;
    private static final String REDIRECT_URL = "http://www.example.com/redirect";
    private static final String CLAIMED_IDENTITY_URL = "http://www.example.com/identity";
    private static final String REQUEST_PATH = "/j_spring_openid_security_check";
    private static final String FILTER_PROCESS_URL = "http://localhost:80" + REQUEST_PATH;
    private static final String DEFAULT_TARGET_URL = FILTER_PROCESS_URL;

    @Before
    public void setUp() throws Exception {
        filter = new OpenIDAuthenticationFilter();
        filter.setConsumer(new MockOpenIDConsumer(REDIRECT_URL));
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        filter.setAuthenticationSuccessHandler(new SavedRequestAwareAuthenticationSuccessHandler());
        successHandler.setDefaultTargetUrl(DEFAULT_TARGET_URL);
        filter.setAuthenticationManager(new AuthenticationManager() {
            public Authentication authenticate(Authentication a) {
                return a;
            }
        });
        filter.afterPropertiesSet();
    }

    @Test
    public void testFilterOperation() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", REQUEST_PATH);
        MockHttpServletResponse response = new MockHttpServletResponse();

        req.setParameter("openid_identifier", CLAIMED_IDENTITY_URL);
        req.setRemoteHost("www.example.com");

        filter.setConsumer(new MockOpenIDConsumer() {
            public String beginConsumption(HttpServletRequest req, String claimedIdentity, String returnToUrl, String realm) throws OpenIDConsumerException {
                assertEquals(CLAIMED_IDENTITY_URL, claimedIdentity);
                assertEquals(DEFAULT_TARGET_URL, returnToUrl);
                assertEquals("http://localhost:80/", realm);
                return REDIRECT_URL;
            }
        });

        FilterChain fc = mock(FilterChain.class);
        filter.doFilter(req, response, fc);
        assertEquals(REDIRECT_URL, response.getRedirectedUrl());
        // Filter chain shouldn't proceed
        verify(fc, never()).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
    }
}
