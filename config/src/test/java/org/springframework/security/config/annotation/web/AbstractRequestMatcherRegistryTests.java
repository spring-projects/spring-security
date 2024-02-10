/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.annotation.web;

import java.util.ArrayList;
import java.util.List;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.Servlet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.config.MockServletContext;
import org.springframework.security.config.TestMockHttpServletMappings;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry.DispatcherServletDelegatingRequestMatcher;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.DispatcherTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link AbstractRequestMatcherRegistry}.
 *
 * @author Joe Grandja
 * @author Marcus Da Coregio
 */
public class AbstractRequestMatcherRegistryTests {

	private static final ObjectPostProcessor<Object> NO_OP_OBJECT_POST_PROCESSOR = new ObjectPostProcessor<Object>() {
		@Override
		public <O> O postProcess(O object) {
			return object;
		}
	};

	private TestRequestMatcherRegistry matcherRegistry;

	private WebApplicationContext context;

	@BeforeEach
	public void setUp() {
		this.matcherRegistry = new TestRequestMatcherRegistry();
		this.context = mock(WebApplicationContext.class);
		given(this.context.getBean(ObjectPostProcessor.class)).willReturn(NO_OP_OBJECT_POST_PROCESSOR);
		given(this.context.getServletContext()).willReturn(MockServletContext.mvc());
		this.matcherRegistry.setApplicationContext(this.context);
		mockMvcIntrospector(true);
	}

	@Test
	public void regexMatchersWhenHttpMethodAndPatternParamsThenReturnRegexRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry
			.requestMatchers(new RegexRequestMatcher("/a.*", HttpMethod.GET.name()));
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(RegexRequestMatcher.class);
	}

	@Test
	public void regexMatchersWhenPatternParamThenReturnRegexRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry
			.requestMatchers(new RegexRequestMatcher("/a.*", null));
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(RegexRequestMatcher.class);
	}

	@Test
	public void antMatchersWhenHttpMethodAndPatternParamsThenReturnAntPathRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry
			.requestMatchers(new AntPathRequestMatcher("/a.*", HttpMethod.GET.name()));
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(AntPathRequestMatcher.class);
	}

	@Test
	public void antMatchersWhenPatternParamThenReturnAntPathRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers(new AntPathRequestMatcher("/a.*"));
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(AntPathRequestMatcher.class);
	}

	@Test
	public void dispatcherTypeMatchersWhenHttpMethodAndPatternParamsThenReturnAntPathRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.dispatcherTypeMatchers(HttpMethod.GET,
				DispatcherType.ASYNC);
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(DispatcherTypeRequestMatcher.class);
	}

	@Test
	public void dispatcherMatchersWhenPatternParamThenReturnAntPathRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.dispatcherTypeMatchers(DispatcherType.INCLUDE);
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(DispatcherTypeRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenPatternAndMvcPresentThenReturnMvcRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers("/path");
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(MvcRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenHttpMethodAndPatternAndMvcPresentThenReturnMvcRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers(HttpMethod.GET, "/path");
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(MvcRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenHttpMethodAndMvcPresentThenReturnMvcRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers(HttpMethod.GET);
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(MvcRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenMvcPresentInClassPathAndMvcIntrospectorBeanNotAvailableThenException() {
		mockMvcIntrospector(false);
		assertThatExceptionOfType(NoSuchBeanDefinitionException.class)
			.isThrownBy(() -> this.matcherRegistry.requestMatchers("/path"))
			.withMessageContaining(
					"Please ensure Spring Security & Spring MVC are configured in a shared ApplicationContext");
	}

	@Test
	public void requestMatchersWhenNoDispatcherServletThenAntPathRequestMatcherType() {
		mockMvcIntrospector(true);
		MockServletContext servletContext = new MockServletContext();
		given(this.context.getServletContext()).willReturn(servletContext);
		servletContext.addServlet("servletOne", Servlet.class).addMapping("/one");
		servletContext.addServlet("servletTwo", Servlet.class).addMapping("/two");
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers("/**");
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(AntPathRequestMatcher.class);
		servletContext.addServlet("servletOne", Servlet.class);
		servletContext.addServlet("servletTwo", Servlet.class);
		requestMatchers = this.matcherRegistry.requestMatchers("/**");
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(AntPathRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenAmbiguousServletsThenException() {
		mockMvcIntrospector(true);
		MockServletContext servletContext = new MockServletContext();
		given(this.context.getServletContext()).willReturn(servletContext);
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/");
		servletContext.addServlet("servletTwo", DispatcherServlet.class).addMapping("/servlet/*");
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.matcherRegistry.requestMatchers("/**"));
	}

	@Test
	public void requestMatchersWhenMultipleDispatcherServletMappingsThenException() {
		mockMvcIntrospector(true);
		MockServletContext servletContext = new MockServletContext();
		given(this.context.getServletContext()).willReturn(servletContext);
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/", "/mvc/*");
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.matcherRegistry.requestMatchers("/**"));
	}

	@Test
	public void requestMatchersWhenPathDispatcherServletAndOtherServletsThenException() {
		mockMvcIntrospector(true);
		MockServletContext servletContext = new MockServletContext();
		given(this.context.getServletContext()).willReturn(servletContext);
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.matcherRegistry.requestMatchers("/**"));
	}

	@Test
	public void requestMatchersWhenUnmappableServletsThenSkips() {
		mockMvcIntrospector(true);
		MockServletContext servletContext = new MockServletContext();
		given(this.context.getServletContext()).willReturn(servletContext);
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/");
		servletContext.addServlet("servletTwo", Servlet.class);
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers("/**");
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isInstanceOf(MvcRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenOnlyDispatcherServletThenAllows() {
		MockServletContext servletContext = new MockServletContext();
		given(this.context.getServletContext()).willReturn(servletContext);
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers("/**");
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isInstanceOf(MvcRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenImplicitServletsThenAllows() {
		mockMvcIntrospector(true);
		MockServletContext servletContext = new MockServletContext();
		given(this.context.getServletContext()).willReturn(servletContext);
		servletContext.addServlet("defaultServlet", Servlet.class);
		servletContext.addServlet("jspServlet", Servlet.class).addMapping("*.jsp", "*.jspx");
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/");
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers("/**");
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isInstanceOf(DispatcherServletDelegatingRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenPathBasedNonDispatcherServletThenAllows() {
		MockServletContext servletContext = new MockServletContext();
		given(this.context.getServletContext()).willReturn(servletContext);
		servletContext.addServlet("path", Servlet.class).addMapping("/services/*");
		servletContext.addServlet("default", DispatcherServlet.class).addMapping("/");
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers("/services/*");
		assertThat(requestMatchers).hasSize(1);
		assertThat(requestMatchers.get(0)).isInstanceOf(DispatcherServletDelegatingRequestMatcher.class);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/services/endpoint");
		request.setHttpServletMapping(TestMockHttpServletMappings.defaultMapping());
		assertThat(requestMatchers.get(0).matcher(request).isMatch()).isTrue();
		request.setHttpServletMapping(TestMockHttpServletMappings.path(request, "/services"));
		request.setServletPath("/services");
		request.setPathInfo("/endpoint");
		assertThat(requestMatchers.get(0).matcher(request).isMatch()).isTrue();
	}

	@Test
	public void matchesWhenDispatcherServletThenMvc() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", DispatcherServlet.class).addMapping("/");
		servletContext.addServlet("path", Servlet.class).addMapping("/services/*");
		MvcRequestMatcher mvc = mock(MvcRequestMatcher.class);
		AntPathRequestMatcher ant = mock(AntPathRequestMatcher.class);
		DispatcherServletDelegatingRequestMatcher requestMatcher = new DispatcherServletDelegatingRequestMatcher(ant,
				mvc, servletContext);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/services/endpoint");
		request.setHttpServletMapping(TestMockHttpServletMappings.defaultMapping());
		assertThat(requestMatcher.matches(request)).isFalse();
		verify(mvc).matches(request);
		verifyNoInteractions(ant);
		request.setHttpServletMapping(TestMockHttpServletMappings.path(request, "/services"));
		assertThat(requestMatcher.matches(request)).isFalse();
		verify(ant).matches(request);
		verifyNoMoreInteractions(mvc);
	}

	private void mockMvcIntrospector(boolean isPresent) {
		ApplicationContext context = this.matcherRegistry.getApplicationContext();
		given(context.containsBean("mvcHandlerMappingIntrospector")).willReturn(isPresent);
	}

	private static class TestRequestMatcherRegistry extends AbstractRequestMatcherRegistry<List<RequestMatcher>> {

		@Override
		public List<RequestMatcher> requestMatchers(RequestMatcher... requestMatchers) {
			return unwrap(super.requestMatchers(requestMatchers));
		}

		@Override
		protected List<RequestMatcher> chainRequestMatchers(List<RequestMatcher> requestMatchers) {
			return requestMatchers;
		}

		private static List<RequestMatcher> unwrap(List<RequestMatcher> wrappedMatchers) {
			List<RequestMatcher> requestMatchers = new ArrayList<>();
			for (RequestMatcher requestMatcher : wrappedMatchers) {
				if (requestMatcher instanceof AbstractRequestMatcherRegistry.DeferredRequestMatcher) {
					requestMatchers.add(((DeferredRequestMatcher) requestMatcher).requestMatcher);
				}
				else {
					requestMatchers.add(requestMatcher);
				}
			}
			return requestMatchers;
		}

	}

}
