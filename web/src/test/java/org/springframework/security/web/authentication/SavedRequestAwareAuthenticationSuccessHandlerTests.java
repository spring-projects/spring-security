package org.springframework.security.web.authentication;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.*;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

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

    @Test
    public void onAuthenticationSuccessHasSavedRequest() throws Exception {
        String redirectUrl = "http://localhost/appcontext/page";
        RedirectStrategy redirectStrategy = mock(RedirectStrategy.class);
        RequestCache requestCache = mock(RequestCache.class);
        SavedRequest savedRequest = mock(SavedRequest.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(savedRequest.getRedirectUrl()).thenReturn(redirectUrl);
        when(requestCache.getRequest(request, response)).thenReturn(savedRequest);

        SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
        handler.setRequestCache(requestCache);
        handler.setRedirectStrategy(redirectStrategy);
        handler.onAuthenticationSuccess(request, response, mock(Authentication.class));

        verify(redirectStrategy).sendRedirect(request, response, redirectUrl);
    }
}