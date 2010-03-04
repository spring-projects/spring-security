package org.springframework.security.web.savedrequest;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.WebAttributes;

public class RequestCacheAwareFilterTests {

    @Test
    public void savedRequestIsRemovedAfterMatch() throws Exception {
        RequestCacheAwareFilter filter = new RequestCacheAwareFilter();
        HttpSessionRequestCache cache = new HttpSessionRequestCache();

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/destination");
        MockHttpServletResponse response = new MockHttpServletResponse();
        cache.saveRequest(request, response);
        assertNotNull(request.getSession().getAttribute(WebAttributes.SAVED_REQUEST));

        filter.doFilter(request, response, new MockFilterChain());
        assertNull(request.getSession().getAttribute(WebAttributes.SAVED_REQUEST));
    }
}
