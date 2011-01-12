package org.springframework.security.web.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.*;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

/**
 *
 * @author Luke Taylor
 */
public class SimpleUrlAuthenticationSuccessHandlerTests {
    @Test
    public void defaultTargetUrlIsUsedIfNoOtherInformationSet() throws Exception {
        SimpleUrlAuthenticationSuccessHandler ash = new SimpleUrlAuthenticationSuccessHandler();

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        ash.onAuthenticationSuccess(request, response, mock(Authentication.class));

        assertEquals("/", response.getRedirectedUrl());
    }

    // SEC-1428
    @Test
    public void redirectIsNotPerformedIfResponseIsCommitted() throws Exception {
        SimpleUrlAuthenticationSuccessHandler ash = new SimpleUrlAuthenticationSuccessHandler("/target");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setCommitted(true);

        ash.onAuthenticationSuccess(request, response, mock(Authentication.class));
        assertNull(response.getRedirectedUrl());
    }

    /**
     * SEC-213
     */
    @Test
    public void targetUrlParameterIsUsedIfPresentAndParameterNameIsSet() throws Exception {
        SimpleUrlAuthenticationSuccessHandler ash = new SimpleUrlAuthenticationSuccessHandler("/defaultTarget");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setParameter("targetUrl", "/target");

        ash.onAuthenticationSuccess(request, response, mock(Authentication.class));
        assertEquals("/defaultTarget", response.getRedirectedUrl());

        // Try with parameter set
        ash.setTargetUrlParameter("targetUrl");
        response = new MockHttpServletResponse();
        ash.onAuthenticationSuccess(request, response, mock(Authentication.class));
        assertEquals("/target", response.getRedirectedUrl());
    }

    @Test
    public void refererIsUsedIfUseRefererIsSet() throws Exception {
        SimpleUrlAuthenticationSuccessHandler ash = new SimpleUrlAuthenticationSuccessHandler("/defaultTarget");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        ash.setUseReferer(true);
        request.addHeader("Referer", "http://www.springsource.com/");

        ash.onAuthenticationSuccess(request, response, mock(Authentication.class));
        assertEquals("http://www.springsource.com/", response.getRedirectedUrl());
    }

    /**
     * SEC-297 fix.
     */
    @Test
    public void absoluteDefaultTargetUrlDoesNotHaveContextPathPrepended() throws Exception {
        SimpleUrlAuthenticationSuccessHandler ash = new SimpleUrlAuthenticationSuccessHandler();
        ash.setDefaultTargetUrl("https://monkeymachine.co.uk/");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        ash.onAuthenticationSuccess(request, response, mock(Authentication.class));

        assertEquals("https://monkeymachine.co.uk/", response.getRedirectedUrl());
    }

}
