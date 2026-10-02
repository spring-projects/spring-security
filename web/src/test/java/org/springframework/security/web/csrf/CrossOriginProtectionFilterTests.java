/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.csrf;

import java.util.List;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link CrossOriginProtectionFilter}.
 *
 * @author Scott Murphy Heiberg
 */
public class CrossOriginProtectionFilterTests {

	private CrossOriginProtectionFilter filter;

	private AccessDeniedHandler accessDeniedHandler;

	private FilterChain filterChain;

	private MockHttpServletResponse response;

	@BeforeEach
	public void setup() {
		this.filter = new CrossOriginProtectionFilter();
		this.accessDeniedHandler = mock(AccessDeniedHandler.class);
		this.filter.setAccessDeniedHandler(this.accessDeniedHandler);
		this.filterChain = mock(FilterChain.class);
		this.response = new MockHttpServletResponse();
	}

	private static MockHttpServletRequest post() {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/transfer");
		request.setScheme("https");
		request.setServerName("bank.example");
		request.setServerPort(443);
		return request;
	}

	@ParameterizedTest
	@ValueSource(strings = { "same-origin", "none" })
	public void doFilterWhenSecFetchSiteFromThisOriginThenContinues(String site) throws Exception {
		MockHttpServletRequest request = post();
		request.addHeader("Sec-Fetch-Site", site);
		this.filter.doFilter(request, this.response, this.filterChain);
		verify(this.filterChain).doFilter(request, this.response);
		verifyNoInteractions(this.accessDeniedHandler);
	}

	@ParameterizedTest
	@ValueSource(strings = { "cross-site", "same-site" })
	public void doFilterWhenSecFetchSiteFromAnotherOriginThenAccessDenied(String site) throws Exception {
		MockHttpServletRequest request = post();
		request.addHeader("Sec-Fetch-Site", site);
		this.filter.doFilter(request, this.response, this.filterChain);
		assertAccessDenied(request, "Cross-origin request rejected: Sec-Fetch-Site is " + site);
	}

	@Test
	public void doFilterWhenSecFetchSiteCrossSiteAndOriginMatchesThenAccessDenied() throws Exception {
		MockHttpServletRequest request = post();
		request.addHeader("Sec-Fetch-Site", "cross-site");
		request.addHeader("Origin", "https://bank.example");
		this.filter.doFilter(request, this.response, this.filterChain);
		assertAccessDenied(request, "Cross-origin request rejected: Sec-Fetch-Site is cross-site");
	}

	@ParameterizedTest
	@ValueSource(strings = { "https://bank.example", "https://bank.example:443" })
	public void doFilterWhenNoSecFetchSiteAndOriginIsRequestOriginThenContinues(String origin) throws Exception {
		MockHttpServletRequest request = post();
		request.addHeader("Origin", origin);
		this.filter.doFilter(request, this.response, this.filterChain);
		verify(this.filterChain).doFilter(request, this.response);
		verifyNoInteractions(this.accessDeniedHandler);
	}

	@ParameterizedTest
	@ValueSource(strings = { "https://evil.example", "http://bank.example", "https://bank.example:8443",
			"https://sub.bank.example", "null" })
	public void doFilterWhenNoSecFetchSiteAndOriginIsAnotherOriginThenAccessDenied(String origin) throws Exception {
		MockHttpServletRequest request = post();
		request.addHeader("Origin", origin);
		this.filter.doFilter(request, this.response, this.filterChain);
		assertAccessDenied(request,
				"Cross-origin request rejected: Origin " + origin + " is not the origin of the request");
	}

	@Test
	public void doFilterWhenNeitherHeaderThenContinues() throws Exception {
		MockHttpServletRequest request = post();
		this.filter.doFilter(request, this.response, this.filterChain);
		verify(this.filterChain).doFilter(request, this.response);
		verifyNoInteractions(this.accessDeniedHandler);
	}

	@ParameterizedTest
	@ValueSource(strings = { "GET", "HEAD", "TRACE", "OPTIONS" })
	public void doFilterWhenSafeMethodFromAnotherOriginThenContinues(String method) throws Exception {
		MockHttpServletRequest request = post();
		request.setMethod(method);
		request.addHeader("Sec-Fetch-Site", "cross-site");
		this.filter.doFilter(request, this.response, this.filterChain);
		verify(this.filterChain).doFilter(request, this.response);
		verifyNoInteractions(this.accessDeniedHandler);
	}

	@Test
	public void doFilterWhenRequireProtectionMatcherDoesNotMatchThenContinues() throws Exception {
		this.filter.setRequireProtectionMatcher((request) -> false);
		MockHttpServletRequest request = post();
		request.addHeader("Sec-Fetch-Site", "cross-site");
		this.filter.doFilter(request, this.response, this.filterChain);
		verify(this.filterChain).doFilter(request, this.response);
		verifyNoInteractions(this.accessDeniedHandler);
	}

	@Test
	public void doFilterWhenSkipRequestThenContinues() throws Exception {
		MockHttpServletRequest request = post();
		request.addHeader("Sec-Fetch-Site", "cross-site");
		CsrfFilter.skipRequest(request);
		this.filter.doFilter(request, this.response, this.filterChain);
		verify(this.filterChain).doFilter(request, this.response);
		verifyNoInteractions(this.accessDeniedHandler);
	}

	@Test
	public void doFilterWhenOriginIsTrustedThenContinues() throws Exception {
		this.filter.setTrustedOrigins(List.of("https://partner.example"));
		MockHttpServletRequest crossSite = post();
		crossSite.addHeader("Sec-Fetch-Site", "cross-site");
		crossSite.addHeader("Origin", "https://Partner.example");
		this.filter.doFilter(crossSite, this.response, this.filterChain);
		verify(this.filterChain).doFilter(crossSite, this.response);
		MockHttpServletRequest olderBrowser = post();
		olderBrowser.addHeader("Origin", "https://partner.example");
		this.filter.doFilter(olderBrowser, this.response, this.filterChain);
		verify(this.filterChain).doFilter(olderBrowser, this.response);
		verifyNoInteractions(this.accessDeniedHandler);
	}

	@Test
	public void doFilterWhenOriginIsNotTrustedThenAccessDenied() throws Exception {
		this.filter.setTrustedOrigins(List.of("https://partner.example"));
		MockHttpServletRequest request = post();
		request.addHeader("Sec-Fetch-Site", "cross-site");
		request.addHeader("Origin", "http://partner.example");
		this.filter.doFilter(request, this.response, this.filterChain);
		assertAccessDenied(request, "Cross-origin request rejected: Sec-Fetch-Site is cross-site");
	}

	@Test
	public void doFilterWhenAccessDeniedByDefaultHandlerThenForbidden() throws Exception {
		CrossOriginProtectionFilter filter = new CrossOriginProtectionFilter();
		MockHttpServletRequest request = post();
		request.addHeader("Sec-Fetch-Site", "cross-site");
		filter.doFilter(request, this.response, this.filterChain);
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
		verifyNoInteractions(this.filterChain);
	}

	@Test
	public void doFilterWhenReportOnlyAndFromAnotherOriginThenContinues() throws Exception {
		this.filter.setReportOnly(true);
		MockHttpServletRequest request = post();
		request.addHeader("Sec-Fetch-Site", "cross-site");
		this.filter.doFilter(request, this.response, this.filterChain);
		verify(this.filterChain).doFilter(request, this.response);
		verifyNoInteractions(this.accessDeniedHandler);
	}

	@Test
	public void doFilterThenDoesNotCreateSession() throws Exception {
		MockHttpServletRequest request = post();
		request.addHeader("Sec-Fetch-Site", "same-origin");
		this.filter.doFilter(request, this.response, this.filterChain);
		assertThat(request.getSession(false)).isNull();
	}

	@Test
	public void setTrustedOriginsWhenAllThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setTrustedOrigins(List.of("*")));
	}

	@Test
	public void setTrustedOriginsWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setTrustedOrigins(null));
	}

	@Test
	public void setRequireProtectionMatcherWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setRequireProtectionMatcher(null));
	}

	@Test
	public void setAccessDeniedHandlerWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setAccessDeniedHandler(null));
	}

	private void assertAccessDenied(MockHttpServletRequest request, String message) throws Exception {
		ArgumentCaptor<AccessDeniedException> exception = ArgumentCaptor.forClass(AccessDeniedException.class);
		verify(this.accessDeniedHandler).handle(any(), any(), exception.capture());
		assertThat(exception.getValue()).isInstanceOf(CrossOriginRequestException.class).hasMessage(message);
		verifyNoInteractions(this.filterChain);
	}

}
