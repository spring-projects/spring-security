/*
 * Copyright 2012-2024 the original author or authors.
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

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.MappingMatch;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletMapping;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.servlet.MockServletContext;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcherFactory.MvcDelegatingRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import org.springframework.web.servlet.handler.MatchableHandlerMapping;
import org.springframework.web.servlet.handler.RequestMatchResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@ExtendWith(MockitoExtension.class)
class MvcRequestMatcherFactoryTests {

	@Mock
	HandlerMappingIntrospector introspector;

	@Mock
	MatchableHandlerMapping handlerMapping;

	MvcRequestMatcherFactory builder;

	@BeforeEach
	void mocks() {
		this.builder = new MvcRequestMatcherFactory(this.introspector, "/servlet/path");
	}

	@Test
	void requestWhenNotDispatcherServletThenUsesAntPath() {
		ServletContext servletContext = MockServletContext.mvc();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/servlet/path");
		MockHttpServletRequest request = new MockHttpServletRequest(servletContext, "GET", "/endpoint");
		MvcDelegatingRequestMatcher matcher = (MvcDelegatingRequestMatcher) this.builder.requestMatcher(HttpMethod.GET,
				"/endpoint");
		RequestMatcher delegateMatcher = matcher.requestMatcher(request);
		assertThat(delegateMatcher).isInstanceOf(AntPathRequestMatcher.class);
	}

	@Test
	void requestWhenDispatcherServletThenUsesMvc() {
		MockHttpServletRequest request = mvcRequest();
		MvcDelegatingRequestMatcher matcher = (MvcDelegatingRequestMatcher) this.builder.requestMatcher(HttpMethod.GET,
				"/endpoint");
		RequestMatcher delegateMatcher = matcher.requestMatcher(request);
		assertThat(delegateMatcher).isInstanceOf(MvcRequestMatcher.class);
	}

	@Test
	void mvcRequestWhenNoMvcMappingThenDoesNotMatch() {
		MockHttpServletRequest request = mvcRequest();
		MvcDelegatingRequestMatcher matcher = (MvcDelegatingRequestMatcher) this.builder.requestMatcher(HttpMethod.GET,
				"/endpoint");
		RequestMatcher delegateMatcher = matcher.requestMatcher(request);
		assertThat(delegateMatcher.matches(request)).isFalse();
	}

	@Test
	void mvcRequestWhenMvcMappingThenMatches() throws Exception {
		given(this.introspector.getMatchableHandlerMapping(any())).willReturn(this.handlerMapping);
		given(this.handlerMapping.match(any(), any())).willReturn(mock(RequestMatchResult.class));
		MockHttpServletRequest request = mvcRequest();
		MvcDelegatingRequestMatcher matcher = (MvcDelegatingRequestMatcher) this.builder.requestMatcher(HttpMethod.GET,
				"/endpoint");
		RequestMatcher delegateMatcher = matcher.requestMatcher(request);
		assertThat(delegateMatcher.matcher(request).isMatch()).isTrue();
	}

	@Test
	void mvcRequestWhenDispatcherServletPathThenRequiresServletPath() {
		MvcRequestMatcherFactory builder = new MvcRequestMatcherFactory(this.introspector);
		MockHttpServletRequest request = mvcRequest();
		MvcDelegatingRequestMatcher matcher = (MvcDelegatingRequestMatcher) builder.requestMatcher(HttpMethod.GET,
				"/endpoint");
		assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> matcher.matcher(request));
	}

	@Test
	void mvcReqwestWhenMockMvcThenUsesMvc() throws Exception {
		WebApplicationContext wac = new GenericWebApplicationContext();
		MockMvc mvc = MockMvcBuilders.standaloneSetup(wac).build();
		MockHttpServletRequest request = mvc.perform(get("/endpoint")).andReturn().getRequest();
		MvcDelegatingRequestMatcher matcher = (MvcDelegatingRequestMatcher) this.builder.requestMatcher(HttpMethod.GET,
				"/endpoint");
		RequestMatcher delegateMatcher = matcher.requestMatcher(request);
		assertThat(delegateMatcher).isInstanceOf(MvcRequestMatcher.class);
	}

	private MockServletContext mvcWithServletPath() {
		MockServletContext servletContext = MockServletContext.mvc();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/servlet/path");
		return servletContext;
	}

	private MockHttpServletRequest mvcRequest() {
		ServletContext servletContext = mvcWithServletPath();
		MockHttpServletRequest request = new MockHttpServletRequest(servletContext, "GET", "/servlet/path/endpoint");
		request.setServletPath("/servlet/path");
		request.setHttpServletMapping(
				new MockHttpServletMapping("/servlet/path", "/servlet/path/*", "dispatcherServlet", MappingMatch.PATH));
		return request;
	}

}
