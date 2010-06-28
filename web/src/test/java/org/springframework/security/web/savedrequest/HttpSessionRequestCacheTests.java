package org.springframework.security.web.savedrequest;

import static org.junit.Assert.*;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.util.RequestMatcher;

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
        assertNotNull(request.getSession().getAttribute(WebAttributes.SAVED_REQUEST));
        assertNotNull(cache.getRequest(request, response));

        MockHttpServletRequest newRequest = new MockHttpServletRequest("POST", "/destination");
        newRequest.setSession(request.getSession());
        assertNull(cache.getMatchingRequest(newRequest, response));

    }

    @Test
    public void requestMatcherDefinesCorrectSubsetOfCachedRequests() throws Exception {
        HttpSessionRequestCache cache = new HttpSessionRequestCache();
        cache.setRequestMatcher(new RequestMatcher() {
            public boolean matches(HttpServletRequest request) {
                return request.getMethod().equals("GET");
            }
        });

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/destination");
        MockHttpServletResponse response = new MockHttpServletResponse();
        cache.saveRequest(request, response);
        assertNull(cache.getRequest(request, response));
        assertNull(cache.getRequest(new MockHttpServletRequest(), new MockHttpServletResponse()));
        assertNull(cache.getMatchingRequest(request, response));
    }


}
