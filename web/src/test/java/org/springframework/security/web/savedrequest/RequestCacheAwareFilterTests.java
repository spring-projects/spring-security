package org.springframework.security.web.savedrequest;

import static org.assertj.core.api.Assertions.*;

import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

public class RequestCacheAwareFilterTests {

	@Test
	public void savedRequestIsRemovedAfterMatch() throws Exception {
		RequestCacheAwareFilter filter = new RequestCacheAwareFilter();
		HttpSessionRequestCache cache = new HttpSessionRequestCache();

		MockHttpServletRequest request = new MockHttpServletRequest("POST",
				"/destination");
		MockHttpServletResponse response = new MockHttpServletResponse();
		cache.saveRequest(request, response);
		assertThat(request.getSession().isNotNull().getAttribute(
				HttpSessionRequestCache.SAVED_REQUEST));

		filter.doFilter(request, response, new MockFilterChain());
		assertThat(request.getSession().isNull().getAttribute(
				HttpSessionRequestCache.SAVED_REQUEST));
	}
}
