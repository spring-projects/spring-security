package org.springframework.security.web.savedrequest;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class HttpSessionRequestCacheTests {

    @Test
    public void originalGetRequestDoesntMatchIncomingPost() {
        HttpSessionRequestCache cache = new HttpSessionRequestCache();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/destination");
        MockHttpServletResponse response = new MockHttpServletResponse();
        cache.saveRequest(request, response);
        assertNotNull(request.getSession().getAttribute(DefaultSavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY));
        assertNotNull(cache.getRequest(request, response));

        MockHttpServletRequest newRequest = new MockHttpServletRequest("POST", "/destination");
        newRequest.setSession(request.getSession());
        assertNull(cache.getMatchingRequest(newRequest, response));

    }

}
