package org.springframework.security.web.savedrequest;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

public class RequestCacheAwareFilterTests {


    @Test
    public void savedRequestIsRemovedAfterMatch() throws Exception {
        RequestCacheAwareFilter filter = new RequestCacheAwareFilter();
        HttpSessionRequestCache cache = new HttpSessionRequestCache();

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/destination");
        MockHttpServletResponse response = new MockHttpServletResponse();
        cache.saveRequest(request, response);
        assertNotNull(request.getSession().getAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY));

        filter.doFilter(request, response, new MockFilterChain());
        assertNull(request.getSession().getAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY));
    }

}
