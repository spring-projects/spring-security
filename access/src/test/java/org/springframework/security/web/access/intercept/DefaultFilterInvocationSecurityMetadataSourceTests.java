/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.access.intercept;

import java.util.Collection;
import java.util.LinkedHashMap;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.servlet.TestMockHttpServletRequests;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests {@link DefaultFilterInvocationSecurityMetadataSource}.
 *
 * @author Ben Alex
 */
@SuppressWarnings("deprecation")
public class DefaultFilterInvocationSecurityMetadataSourceTests {

	private DefaultFilterInvocationSecurityMetadataSource fids;

	private Collection<ConfigAttribute> def = SecurityConfig.createList("ROLE_ONE");

	private void createFids(String pattern, HttpMethod method) {
		LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<>();
		requestMap.put(PathPatternRequestMatcher.pathPattern(method, pattern), this.def);
		this.fids = new DefaultFilterInvocationSecurityMetadataSource(requestMap);
	}

	@Test
	public void lookupNotRequiringExactMatchSucceedsIfNotMatching() {
		createFids("/secure/super/**", null);
		FilterInvocation fi = createFilterInvocation("/secure/super/somefile.html", null, null, "GET");
		assertThat(this.fids.getAttributes(fi)).isEqualTo(this.def);
	}

	/**
	 * SEC-501. Note that as of 2.0, lower case comparisons are the default for this
	 * class.
	 */
	@Test
	public void lookupNotRequiringExactMatchSucceedsIfSecureUrlPathContainsUpperCase() {
		createFids("/secure/super/**", null);
		FilterInvocation fi = createFilterInvocation("/secure", "/super/somefile.html", null, "GET");
		Collection<ConfigAttribute> response = this.fids.getAttributes(fi);
		assertThat(response).isEqualTo(this.def);
	}

	@Test
	public void lookupRequiringExactMatchIsSuccessful() {
		createFids("/SeCurE/super/**", null);
		FilterInvocation fi = createFilterInvocation("/SeCurE/super/somefile.html", null, null, "GET");
		Collection<ConfigAttribute> response = this.fids.getAttributes(fi);
		assertThat(response).isEqualTo(this.def);
	}

	@Test
	public void lookupRequiringExactMatchWithAdditionalSlashesIsSuccessful() {
		createFids("/someAdminPage.html**", null);
		FilterInvocation fi = createFilterInvocation("/someAdminPage.html", null, "a=/test", "GET");
		Collection<ConfigAttribute> response = this.fids.getAttributes(fi);
		assertThat(response); // see SEC-161 (it should truncate after ?
								// sign).isEqualTo(def)
	}

	@Test
	public void httpMethodLookupSucceeds() {
		createFids("/somepage**", HttpMethod.GET);
		FilterInvocation fi = createFilterInvocation("/somepage", null, null, "GET");
		Collection<ConfigAttribute> attrs = this.fids.getAttributes(fi);
		assertThat(attrs).isEqualTo(this.def);
	}

	@Test
	public void generalMatchIsUsedIfNoMethodSpecificMatchExists() {
		createFids("/somepage**", null);
		FilterInvocation fi = createFilterInvocation("/somepage", null, null, "GET");
		Collection<ConfigAttribute> attrs = this.fids.getAttributes(fi);
		assertThat(attrs).isEqualTo(this.def);
	}

	@Test
	public void requestWithDifferentHttpMethodDoesntMatch() {
		createFids("/somepage**", HttpMethod.GET);
		FilterInvocation fi = createFilterInvocation("/somepage", null, null, "POST");
		Collection<ConfigAttribute> attrs = this.fids.getAttributes(fi);
		assertThat(attrs).isEmpty();
	}

	// SEC-1236
	@Test
	public void mixingPatternsWithAndWithoutHttpMethodsIsSupported() {
		LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = new LinkedHashMap<>();
		Collection<ConfigAttribute> userAttrs = SecurityConfig.createList("A");
		requestMap.put(PathPatternRequestMatcher.pathPattern("/user/**"), userAttrs);
		requestMap.put(PathPatternRequestMatcher.pathPattern(HttpMethod.GET, "/teller/**"),
				SecurityConfig.createList("B"));
		this.fids = new DefaultFilterInvocationSecurityMetadataSource(requestMap);
		FilterInvocation fi = createFilterInvocation("/user", null, null, "GET");
		Collection<ConfigAttribute> attrs = this.fids.getAttributes(fi);
		assertThat(attrs).isEqualTo(userAttrs);
	}

	/**
	 * Check fixes for SEC-321
	 */
	@Test
	public void extraQuestionMarkStillMatches() {
		createFids("/someAdminPage.html*", null);
		FilterInvocation fi = createFilterInvocation("/someAdminPage.html", null, null, "GET");
		Collection<ConfigAttribute> response = this.fids.getAttributes(fi);
		assertThat(response).isEqualTo(this.def);
		fi = createFilterInvocation("/someAdminPage.html", null, "?", "GET");
		response = this.fids.getAttributes(fi);
		assertThat(response).isEqualTo(this.def);
	}

	private FilterInvocation createFilterInvocation(String servletPath, String pathInfo, String queryString,
			String method) {
		MockHttpServletRequest request = TestMockHttpServletRequests.request(method)
			.requestUri(null, servletPath, pathInfo)
			.queryString(queryString)
			.build();
		return new FilterInvocation(request, new MockHttpServletResponse(), mock(FilterChain.class));
	}

}
