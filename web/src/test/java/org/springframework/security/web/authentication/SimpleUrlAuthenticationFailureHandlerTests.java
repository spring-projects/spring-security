package org.springframework.security.web.authentication;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;

/**
 *
 * @author Luke Taylor
 */
public class SimpleUrlAuthenticationFailureHandlerTests {

    @Test
    public void error401IsReturnedIfNoUrlIsSet() throws Exception {
        SimpleUrlAuthenticationFailureHandler afh = new SimpleUrlAuthenticationFailureHandler();
        RedirectStrategy rs = mock(RedirectStrategy.class);
        afh.setRedirectStrategy(rs);
        assertSame(rs, afh.getRedirectStrategy());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        afh.onAuthenticationFailure(request, response, mock(AuthenticationException.class));
        assertEquals(401, response.getStatus());
    }

    @Test
    public void exceptionIsSavedToSessionOnRedirect() throws Exception {
        SimpleUrlAuthenticationFailureHandler afh = new SimpleUrlAuthenticationFailureHandler();
        afh.setDefaultFailureUrl("/target");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        AuthenticationException e = mock(AuthenticationException.class);

        afh.onAuthenticationFailure(request, response, e);
        assertSame(e, request.getSession().getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION));
        assertEquals("/target", response.getRedirectedUrl());
    }

    @Test
    public void exceptionIsNotSavedIfAllowSessionCreationIsFalse() throws Exception {
        SimpleUrlAuthenticationFailureHandler afh = new SimpleUrlAuthenticationFailureHandler("/target");
        afh.setAllowSessionCreation(false);
        assertFalse(afh.isAllowSessionCreation());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        afh.onAuthenticationFailure(request, response, mock(AuthenticationException.class));
        assertNull(request.getSession(false));
    }

    // SEC-462
    @Test
    public void responseIsForwardedIfUseForwardIsTrue() throws Exception {
        SimpleUrlAuthenticationFailureHandler afh = new SimpleUrlAuthenticationFailureHandler("/target");
        afh.setUseForward(true);
        assertTrue(afh.isUseForward());

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException e = mock(AuthenticationException.class);

        afh.onAuthenticationFailure(request, response, e);
        assertNull(request.getSession(false));
        assertNull(response.getRedirectedUrl());
        assertEquals("/target", response.getForwardedUrl());
        // Request scope should be used for forward
        assertSame(e, request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION));
    }

}
