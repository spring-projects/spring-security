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
    public void targetUrlParameterIsUsedIfPresent() throws Exception {
        SimpleUrlAuthenticationSuccessHandler ash = new SimpleUrlAuthenticationSuccessHandler("/defaultTarget");
        ash.setUseTargetUrlparameter(true);
        ash.setTargetUrlParameter("targetUrl");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        request.setParameter("targetUrl", "/target");

        ash.onAuthenticationSuccess(request, response, mock(Authentication.class));

        assertEquals("/target", response.getRedirectedUrl());
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
