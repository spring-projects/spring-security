/*
 * Copyright 2012-2022 the original author or authors.
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

package org.springframework.security.web.servlet.util.matcher;

import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import org.springframework.web.servlet.handler.MatchableHandlerMapping;
import org.springframework.web.servlet.handler.RequestMatchResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Rob Winch
 * @author Eddú Meléndez
 * @author Evgeniy Cheban
 */
@ExtendWith(MockitoExtension.class)
public class MvcRequestMatcherTests {

	@Mock
	HandlerMappingIntrospector introspector;

	@Mock
	MatchableHandlerMapping mapping;

	@Mock
	RequestMatchResult result;

	@Captor
	ArgumentCaptor<String> pattern;

	MockHttpServletRequest request;

	MvcRequestMatcher matcher;

	@BeforeEach
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.request.setMethod("GET");
		this.request.setServletPath("/path");
		this.matcher = new MvcRequestMatcher(this.introspector, "/path");
	}

	@Test
	public void extractUriTemplateVariablesSuccess() throws Exception {
		this.matcher = new MvcRequestMatcher(this.introspector, "/{p}");
		given(this.introspector.getMatchableHandlerMapping(this.request)).willReturn(null);
		assertThat(this.matcher.extractUriTemplateVariables(this.request)).containsEntry("p", "path");
		assertThat(this.matcher.matcher(this.request).getVariables()).containsEntry("p", "path");
	}

	@Test
	public void extractUriTemplateVariablesFail() throws Exception {
		given(this.result.extractUriTemplateVariables()).willReturn(Collections.<String, String>emptyMap());
		given(this.introspector.getMatchableHandlerMapping(this.request)).willReturn(this.mapping);
		given(this.mapping.match(eq(this.request), this.pattern.capture())).willReturn(this.result);
		assertThat(this.matcher.extractUriTemplateVariables(this.request)).isEmpty();
		assertThat(this.matcher.matcher(this.request).getVariables()).isEmpty();
	}

	@Test
	public void extractUriTemplateVariablesDefaultSuccess() throws Exception {
		this.matcher = new MvcRequestMatcher(this.introspector, "/{p}");
		given(this.introspector.getMatchableHandlerMapping(this.request)).willReturn(null);
		assertThat(this.matcher.extractUriTemplateVariables(this.request)).containsEntry("p", "path");
		assertThat(this.matcher.matcher(this.request).getVariables()).containsEntry("p", "path");
	}

	@Test
	public void extractUriTemplateVariablesDefaultFail() throws Exception {
		this.matcher = new MvcRequestMatcher(this.introspector, "/nomatch/{p}");
		given(this.introspector.getMatchableHandlerMapping(this.request)).willReturn(null);
		assertThat(this.matcher.extractUriTemplateVariables(this.request)).isEmpty();
		assertThat(this.matcher.matcher(this.request).getVariables()).isEmpty();
	}

	@Test
	public void matchesServletPathTrue() throws Exception {
		given(this.introspector.getMatchableHandlerMapping(this.request)).willReturn(this.mapping);
		given(this.mapping.match(eq(this.request), this.pattern.capture())).willReturn(this.result);
		this.matcher.setServletPath("/spring");
		this.request.setServletPath("/spring");
		assertThat(this.matcher.matches(this.request)).isTrue();
		assertThat(this.pattern.getValue()).isEqualTo("/path");
	}

	@Test
	public void matchesServletPathFalse() {
		this.matcher.setServletPath("/spring");
		this.request.setServletPath("/");
		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void matchesPathOnlyTrue() throws Exception {
		given(this.introspector.getMatchableHandlerMapping(this.request)).willReturn(this.mapping);
		given(this.mapping.match(eq(this.request), this.pattern.capture())).willReturn(this.result);
		assertThat(this.matcher.matches(this.request)).isTrue();
		assertThat(this.pattern.getValue()).isEqualTo("/path");
	}

	@Test
	public void matchesDefaultMatches() throws Exception {
		given(this.introspector.getMatchableHandlerMapping(this.request)).willReturn(null);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchesDefaultDoesNotMatch() throws Exception {
		this.request.setServletPath("/other");
		given(this.introspector.getMatchableHandlerMapping(this.request)).willReturn(null);
		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void matchesPathOnlyFalse() throws Exception {
		given(this.introspector.getMatchableHandlerMapping(this.request)).willReturn(this.mapping);
		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void matchesMethodAndPathTrue() throws Exception {
		this.matcher.setMethod(HttpMethod.GET);
		given(this.introspector.getMatchableHandlerMapping(this.request)).willReturn(this.mapping);
		given(this.mapping.match(eq(this.request), this.pattern.capture())).willReturn(this.result);
		assertThat(this.matcher.matches(this.request)).isTrue();
		assertThat(this.pattern.getValue()).isEqualTo("/path");
	}

	@Test
	public void matchesMethodAndPathFalseMethod() {
		this.matcher.setMethod(HttpMethod.POST);
		assertThat(this.matcher.matches(this.request)).isFalse();
		// method compare should be done first since faster
		verifyNoMoreInteractions(this.introspector);
	}

	/**
	 * Malicious users can specify any HTTP Method to create a stacktrace and try to
	 * expose useful information about the system. We should ensure we ignore invalid HTTP
	 * methods.
	 */
	@Test
	public void matchesInvalidMethodOnRequest() {
		this.matcher.setMethod(HttpMethod.GET);
		this.request.setMethod("invalid");
		assertThat(this.matcher.matches(this.request)).isFalse();
		// method compare should be done first since faster
		verifyNoMoreInteractions(this.introspector);
	}

	@Test
	public void matchesMethodAndPathFalsePath() throws Exception {
		this.matcher.setMethod(HttpMethod.GET);
		given(this.introspector.getMatchableHandlerMapping(this.request)).willReturn(this.mapping);
		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void matchesGetMatchableHandlerMappingNull() {
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchesGetMatchableHandlerMappingThrows() throws Exception {
		given(this.introspector.getMatchableHandlerMapping(this.request))
				.willThrow(new HttpRequestMethodNotSupportedException(this.request.getMethod()));
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void toStringWhenAll() {
		this.matcher.setMethod(HttpMethod.GET);
		this.matcher.setServletPath("/spring");
		assertThat(this.matcher.toString()).isEqualTo("Mvc [pattern='/path', servletPath='/spring', GET]");
	}

	@Test
	public void toStringWhenHttpMethod() {
		this.matcher.setMethod(HttpMethod.GET);
		assertThat(this.matcher.toString()).isEqualTo("Mvc [pattern='/path', GET]");
	}

	@Test
	public void toStringWhenServletPath() {
		this.matcher.setServletPath("/spring");
		assertThat(this.matcher.toString()).isEqualTo("Mvc [pattern='/path', servletPath='/spring']");
	}

	@Test
	public void toStringWhenOnlyPattern() {
		assertThat(this.matcher.toString()).isEqualTo("Mvc [pattern='/path']");
	}

	@Test
	public void matcherWhenMethodNotMatchesThenNotMatchResult() {
		this.matcher.setMethod(HttpMethod.POST);
		assertThat(this.matcher.matcher(this.request).isMatch()).isFalse();
	}

	@Test
	public void matcherWhenMethodMatchesThenMatchResult() {
		this.matcher.setMethod(HttpMethod.GET);
		assertThat(this.matcher.matcher(this.request).isMatch()).isTrue();
	}

	@Test
	public void matcherWhenServletPathNotMatchesThenNotMatchResult() {
		this.matcher.setServletPath("/spring");
		assertThat(this.matcher.matcher(this.request).isMatch()).isFalse();
	}

	@Test
	public void matcherWhenServletPathMatchesThenMatchResult() {
		this.matcher.setServletPath("/path");
		assertThat(this.matcher.matcher(this.request).isMatch()).isTrue();
	}

	@Test
	public void builderWhenServletPathThenServletPathPresent() {
		MvcRequestMatcher matcher = new MvcRequestMatcher.Builder(this.introspector).servletPath("/path")
				.pattern("/endpoint");
		assertThat(matcher.getServletPath()).isEqualTo("/path");
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/endpoint");
		assertThat(ReflectionTestUtils.getField(matcher, "method")).isNull();
	}

	@Test
	public void builderWhenPatternThenPatternPresent() {
		MvcRequestMatcher matcher = new MvcRequestMatcher.Builder(this.introspector).pattern("/endpoint");
		assertThat(matcher.getServletPath()).isNull();
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/endpoint");
		assertThat(ReflectionTestUtils.getField(matcher, "method")).isNull();
	}

	@Test
	public void builderWhenMethodAndPatternThenMethodAndPatternPresent() {
		MvcRequestMatcher matcher = new MvcRequestMatcher.Builder(this.introspector).pattern(HttpMethod.GET,
				"/endpoint");
		assertThat(matcher.getServletPath()).isNull();
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/endpoint");
		assertThat(ReflectionTestUtils.getField(matcher, "method")).isEqualTo(HttpMethod.GET);
	}

}
