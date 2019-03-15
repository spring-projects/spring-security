/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
		assertThat(request.getSession().getAttribute(
				HttpSessionRequestCache.SAVED_REQUEST)).isNotNull();

		filter.doFilter(request, response, new MockFilterChain());
		assertThat(request.getSession().getAttribute(
				HttpSessionRequestCache.SAVED_REQUEST)).isNull();
	}
}
