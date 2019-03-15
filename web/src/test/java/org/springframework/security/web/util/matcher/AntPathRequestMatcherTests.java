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

package org.springframework.security.web.util.matcher;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * @author Luke Taylor
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class AntPathRequestMatcherTests {

	@Mock
	private HttpServletRequest request;

	@Test
	public void singleWildcardMatchesAnyPath() {
		AntPathRequestMatcher matcher = new AntPathRequestMatcher("/**");
		assertThat(matcher.getPattern()).isEqualTo("/**");

		assertThat(matcher.matches(createRequest("/blah"))).isTrue();

		matcher = new AntPathRequestMatcher("**");
		assertThat(matcher.matches(createRequest("/blah"))).isTrue();
		assertThat(matcher.matches(createRequest(""))).isTrue();
	}

	@Test
	public void trailingWildcardMatchesCorrectly() {
		AntPathRequestMatcher matcher = new AntPathRequestMatcher("/blah/blAh/**", null,
				false);
		assertThat(matcher.matches(createRequest("/BLAH/blah"))).isTrue();
		assertThat(matcher.matches(createRequest("/blah/bleh"))).isFalse();
		assertThat(matcher.matches(createRequest("/blah/blah/"))).isTrue();
		assertThat(matcher.matches(createRequest("/blah/blah/xxx"))).isTrue();
		assertThat(matcher.matches(createRequest("/blah/blaha"))).isFalse();
		assertThat(matcher.matches(createRequest("/blah/bleh/"))).isFalse();
		MockHttpServletRequest request = createRequest("/blah/");

		request.setPathInfo("blah/bleh");
		assertThat(matcher.matches(request)).isTrue();

		matcher = new AntPathRequestMatcher("/bl?h/blAh/**", null, false);
		assertThat(matcher.matches(createRequest("/BLAH/Blah/aaa/"))).isTrue();
		assertThat(matcher.matches(createRequest("/bleh/Blah"))).isTrue();

		matcher = new AntPathRequestMatcher("/blAh/**/blah/**", null, false);
		assertThat(matcher.matches(createRequest("/blah/blah"))).isTrue();
		assertThat(matcher.matches(createRequest("/blah/bleh"))).isFalse();
		assertThat(matcher.matches(createRequest("/blah/aaa/blah/bbb"))).isTrue();
	}

	@Test
	public void trailingWildcardWithVariableMatchesCorrectly() {
		AntPathRequestMatcher matcher = new AntPathRequestMatcher("/{id}/blAh/**", null,
				false);
		assertThat(matcher.matches(createRequest("/1234/blah"))).isTrue();
		assertThat(matcher.matches(createRequest("/4567/bleh"))).isFalse();
		assertThat(matcher.matches(createRequest("/paskos/blah/"))).isTrue();
		assertThat(matcher.matches(createRequest("/12345/blah/xxx"))).isTrue();
		assertThat(matcher.matches(createRequest("/12345/blaha"))).isFalse();
		assertThat(matcher.matches(createRequest("/paskos/bleh/"))).isFalse();
	}

	@Test
	public void nontrailingWildcardWithVariableMatchesCorrectly() {
		AntPathRequestMatcher matcher = new AntPathRequestMatcher("/**/{id}");
		assertThat(matcher.matches(createRequest("/blah/1234"))).isTrue();
		assertThat(matcher.matches(createRequest("/bleh/4567"))).isTrue();
		assertThat(matcher.matches(createRequest("/paskos/blah/"))).isTrue();
		assertThat(matcher.matches(createRequest("/12345/blah/xxx"))).isTrue();
		assertThat(matcher.matches(createRequest("/12345/blaha"))).isTrue();
		assertThat(matcher.matches(createRequest("/paskos/bleh/"))).isTrue();
	}

	@Test
	public void requestHasNullMethodMatches() {
		AntPathRequestMatcher matcher = new AntPathRequestMatcher("/something/*", "GET");
		HttpServletRequest request = createRequestWithNullMethod("/something/here");
		assertThat(matcher.matches(request)).isTrue();
	}

	// SEC-2084
	@Test
	public void requestHasNullMethodNoMatch() {
		AntPathRequestMatcher matcher = new AntPathRequestMatcher("/something/*", "GET");
		HttpServletRequest request = createRequestWithNullMethod("/nomatch");
		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void requestHasNullMethodAndNullMatcherMatches() {
		AntPathRequestMatcher matcher = new AntPathRequestMatcher("/something/*");
		MockHttpServletRequest request = createRequest("/something/here");
		request.setMethod(null);
		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void requestHasNullMethodAndNullMatcherNoMatch() {
		AntPathRequestMatcher matcher = new AntPathRequestMatcher("/something/*");
		MockHttpServletRequest request = createRequest("/nomatch");
		request.setMethod(null);
		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void exactMatchOnlyMatchesIdenticalPath() throws Exception {
		AntPathRequestMatcher matcher = new AntPathRequestMatcher("/login.html");
		assertThat(matcher.matches(createRequest("/login.html"))).isTrue();
		assertThat(matcher.matches(createRequest("/login.html/"))).isFalse();
		assertThat(matcher.matches(createRequest("/login.html/blah"))).isFalse();
	}

	@Test
	public void httpMethodSpecificMatchOnlyMatchesRequestsWithCorrectMethod()
			throws Exception {
		AntPathRequestMatcher matcher = new AntPathRequestMatcher("/blah", "GET");
		MockHttpServletRequest request = createRequest("/blah");
		request.setMethod("GET");
		assertThat(matcher.matches(request)).isTrue();
		request.setMethod("POST");
		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void caseSensitive() throws Exception {
		MockHttpServletRequest request = createRequest("/UPPER");
		assertThat(new AntPathRequestMatcher("/upper", null, true).matches(request))
				.isFalse();
		assertThat(new AntPathRequestMatcher("/upper", "POST", true).matches(request))
				.isFalse();
		assertThat(new AntPathRequestMatcher("/upper", "GET", true).matches(request))
				.isFalse();

		assertThat(new AntPathRequestMatcher("/upper", null, false).matches(request))
				.isTrue();
		assertThat(new AntPathRequestMatcher("/upper", "POST", false).matches(request))
				.isTrue();
	}

	@Test
	public void spacesInPathSegmentsAreNotIgnored() {
		AntPathRequestMatcher matcher = new AntPathRequestMatcher("/path/*/bar");
		MockHttpServletRequest request = createRequest("/path /foo/bar");
		assertThat(matcher.matches(request)).isFalse();

		matcher = new AntPathRequestMatcher("/path/foo");
		request = createRequest("/path /foo");
		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void equalsBehavesCorrectly() throws Exception {
		// Both universal wildcard options should be equal
		assertThat(new AntPathRequestMatcher("**"))
				.isEqualTo(new AntPathRequestMatcher("/**"));
		assertThat(new AntPathRequestMatcher("/xyz"))
				.isEqualTo(new AntPathRequestMatcher("/xyz"));
		assertThat(new AntPathRequestMatcher("/xyz", "POST"))
				.isEqualTo(new AntPathRequestMatcher("/xyz", "POST"));
		assertThat(new AntPathRequestMatcher("/xyz", "POST"))
				.isNotEqualTo(new AntPathRequestMatcher("/xyz", "GET"));
		assertThat(new AntPathRequestMatcher("/xyz"))
				.isNotEqualTo(new AntPathRequestMatcher("/xxx"));
		assertThat(new AntPathRequestMatcher("/xyz").equals(AnyRequestMatcher.INSTANCE))
				.isFalse();
		assertThat(new AntPathRequestMatcher("/xyz", "GET", false))
				.isNotEqualTo(new AntPathRequestMatcher("/xyz", "GET", true));
	}

	@Test
	public void toStringIsOk() throws Exception {
		new AntPathRequestMatcher("/blah").toString();
		new AntPathRequestMatcher("/blah", "GET").toString();
	}

	// SEC-2831
	@Test
	public void matchesWithInvalidMethod() {
		AntPathRequestMatcher matcher = new AntPathRequestMatcher("/blah", "GET");
		MockHttpServletRequest request = createRequest("/blah");
		request.setMethod("INVALID");

		assertThat(matcher.matches(request)).isFalse();
	}

	private HttpServletRequest createRequestWithNullMethod(String path) {
		when(this.request.getQueryString()).thenReturn("doesntMatter");
		when(this.request.getServletPath()).thenReturn(path);
		return this.request;
	}

	private MockHttpServletRequest createRequest(String path) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("doesntMatter");
		request.setServletPath(path);
		request.setMethod("POST");

		return request;
	}
}
