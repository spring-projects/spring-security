/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.openid;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import java.net.URI;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

/**
 * @deprecated The OpenID 1.0 and 2.0 protocols have been deprecated and users are
 * <a href="https://openid.net/specs/openid-connect-migration-1_0.html">encouraged to migrate</a>
 * to <a href="https://openid.net/connect/">OpenID Connect</a>.
 */
public class OpenIDAuthenticationFilterTests {

	OpenIDAuthenticationFilter filter;
	private static final String REDIRECT_URL = "https://www.example.com/redirect";
	private static final String CLAIMED_IDENTITY_URL = "https://www.example.com/identity";
	private static final String REQUEST_PATH = "/login/openid";
	private static final String FILTER_PROCESS_URL = "http://localhost:8080"
			+ REQUEST_PATH;
	private static final String DEFAULT_TARGET_URL = FILTER_PROCESS_URL;

	@Before
	public void setUp() {
		filter = new OpenIDAuthenticationFilter();
		filter.setConsumer(new MockOpenIDConsumer(REDIRECT_URL));
		SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
		filter.setAuthenticationSuccessHandler(new SavedRequestAwareAuthenticationSuccessHandler());
		successHandler.setDefaultTargetUrl(DEFAULT_TARGET_URL);
		filter.setAuthenticationManager(a -> a);
		filter.afterPropertiesSet();
	}

	@Test
	public void testFilterOperation() throws Exception {
		MockHttpServletRequest req = new MockHttpServletRequest();
		req.setServletPath(REQUEST_PATH);
		req.setRequestURI(REQUEST_PATH);
		req.setServerPort(8080);
		MockHttpServletResponse response = new MockHttpServletResponse();

		req.setParameter("openid_identifier", " " + CLAIMED_IDENTITY_URL);
		req.setRemoteHost("www.example.com");

		filter.setConsumer(new MockOpenIDConsumer() {
			public String beginConsumption(HttpServletRequest req,
					String claimedIdentity, String returnToUrl, String realm) {
				assertThat(claimedIdentity).isEqualTo(CLAIMED_IDENTITY_URL);
				assertThat(returnToUrl).isEqualTo(DEFAULT_TARGET_URL);
				assertThat(realm).isEqualTo("http://localhost:8080/");
				return REDIRECT_URL;
			}
		});

		FilterChain fc = mock(FilterChain.class);
		filter.doFilter(req, response, fc);
		assertThat(response.getRedirectedUrl()).isEqualTo(REDIRECT_URL);
		// Filter chain shouldn't proceed
		verify(fc, never()).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	/**
	 * Tests that the filter encodes any query parameters on the return_to URL.
	 */
	@Test
	public void encodesUrlParameters() throws Exception {
		// Arbitrary parameter name and value that will both need to be encoded:
		String paramName = "foo&bar";
		String paramValue = "https://example.com/path?a=b&c=d";
		MockHttpServletRequest req = new MockHttpServletRequest("GET", REQUEST_PATH);
		req.addParameter(paramName, paramValue);
		filter.setReturnToUrlParameters(Collections.singleton(paramName));

		URI returnTo = new URI(filter.buildReturnToUrl(req));
		String query = returnTo.getRawQuery();
		assertThat(count(query, '=')).isEqualTo(1);
		assertThat(count(query, '&')).isZero();
	}

	/**
	 * Counts the number of occurrences of {@code c} in {@code s}.
	 */
	private static int count(String s, char c) {
		int count = 0;
		for (char ch : s.toCharArray()) {
			if (c == ch) {
				count += 1;
			}
		}
		return count;
	}
}
