/*
 * Copyright 2002-2022 the original author or authors.
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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.List;

import javax.servlet.DispatcherType;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.DispatcherTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link AbstractRequestMatcherRegistry}.
 *
 * @author Joe Grandja
 */
public class AbstractRequestMatcherRegistryTests {

	private static final ObjectPostProcessor<Object> NO_OP_OBJECT_POST_PROCESSOR = new ObjectPostProcessor<Object>() {
		@Override
		public <O> O postProcess(O object) {
			return object;
		}
	};

	private TestRequestMatcherRegistry matcherRegistry;

	@BeforeEach
	public void setUp() {
		this.matcherRegistry = new TestRequestMatcherRegistry();
		ApplicationContext context = mock(ApplicationContext.class);
		given(context.getBean(ObjectPostProcessor.class)).willReturn(NO_OP_OBJECT_POST_PROCESSOR);
		this.matcherRegistry.setApplicationContext(context);
	}

	@Test
	public void regexMatchersWhenHttpMethodAndPatternParamsThenReturnRegexRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.regexMatchers(HttpMethod.GET, "/a.*");
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers.size()).isEqualTo(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(RegexRequestMatcher.class);
	}

	@Test
	public void regexMatchersWhenPatternParamThenReturnRegexRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.regexMatchers("/a.*");
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers.size()).isEqualTo(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(RegexRequestMatcher.class);
	}

	@Test
	public void antMatchersWhenHttpMethodAndPatternParamsThenReturnAntPathRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.antMatchers(HttpMethod.GET, "/a.*");
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers.size()).isEqualTo(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(AntPathRequestMatcher.class);
	}

	@Test
	public void antMatchersWhenPatternParamThenReturnAntPathRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.antMatchers("/a.*");
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers.size()).isEqualTo(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(AntPathRequestMatcher.class);
	}

	@Test
	public void dispatcherTypeMatchersWhenHttpMethodAndPatternParamsThenReturnAntPathRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.dispatcherTypeMatchers(HttpMethod.GET,
				DispatcherType.ASYNC);
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers.size()).isEqualTo(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(DispatcherTypeRequestMatcher.class);
	}

	@Test
	public void dispatcherMatchersWhenPatternParamThenReturnAntPathRequestMatcherType() {
		List<RequestMatcher> requestMatchers = this.matcherRegistry.dispatcherTypeMatchers(DispatcherType.INCLUDE);
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers.size()).isEqualTo(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(DispatcherTypeRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenPatternAndMvcPresentThenReturnMvcRequestMatcherType() throws Exception {
		mockMvcPresentClasspath(true);
		mockMvcIntrospector(true);
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers("/path");
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers.size()).isEqualTo(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(MvcRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenHttpMethodAndPatternAndMvcPresentThenReturnMvcRequestMatcherType() throws Exception {
		mockMvcPresentClasspath(true);
		mockMvcIntrospector(true);
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers(HttpMethod.GET, "/path");
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers.size()).isEqualTo(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(MvcRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenHttpMethodAndMvcPresentThenReturnMvcRequestMatcherType() throws Exception {
		mockMvcPresentClasspath(true);
		mockMvcIntrospector(true);
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers(HttpMethod.GET);
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers.size()).isEqualTo(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(MvcRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenPatternAndMvcNotPresentThenReturnAntPathRequestMatcherType() throws Exception {
		mockMvcPresentClasspath(false);
		mockMvcIntrospector(false);
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers("/path");
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers.size()).isEqualTo(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(AntPathRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenHttpMethodAndPatternAndMvcNotPresentThenReturnAntPathRequestMatcherType()
			throws Exception {
		mockMvcPresentClasspath(false);
		mockMvcIntrospector(false);
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers(HttpMethod.GET, "/path");
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers.size()).isEqualTo(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(AntPathRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenHttpMethodAndMvcNotPresentThenReturnAntPathMatcherType() throws Exception {
		mockMvcPresentClasspath(false);
		mockMvcIntrospector(false);
		List<RequestMatcher> requestMatchers = this.matcherRegistry.requestMatchers(HttpMethod.GET);
		assertThat(requestMatchers).isNotEmpty();
		assertThat(requestMatchers.size()).isEqualTo(1);
		assertThat(requestMatchers.get(0)).isExactlyInstanceOf(AntPathRequestMatcher.class);
	}

	@Test
	public void requestMatchersWhenMvcPresentInClassPathAndMvcIntrospectorBeanNotAvailableThenException()
			throws Exception {
		mockMvcPresentClasspath(true);
		mockMvcIntrospector(false);
		assertThatExceptionOfType(NoSuchBeanDefinitionException.class)
				.isThrownBy(() -> this.matcherRegistry.requestMatchers("/path")).withMessageContaining(
						"Please ensure Spring Security & Spring MVC are configured in a shared ApplicationContext");
	}

	private void mockMvcIntrospector(boolean isPresent) {
		ApplicationContext context = this.matcherRegistry.getApplicationContext();
		given(context.containsBean("mvcHandlerMappingIntrospector")).willReturn(isPresent);
	}

	private void mockMvcPresentClasspath(Object newValue) throws Exception {
		Field mvcPresentField = AbstractRequestMatcherRegistry.class.getDeclaredField("mvcPresent");
		mvcPresentField.setAccessible(true);
		Field modifiersField = Field.class.getDeclaredField("modifiers");
		modifiersField.setAccessible(true);
		modifiersField.setInt(mvcPresentField, mvcPresentField.getModifiers() & ~Modifier.FINAL);
		mvcPresentField.set(null, newValue);
	}

	private static class TestRequestMatcherRegistry extends AbstractRequestMatcherRegistry<List<RequestMatcher>> {

		@Override
		public List<RequestMatcher> mvcMatchers(String... mvcPatterns) {
			return null;
		}

		@Override
		public List<RequestMatcher> mvcMatchers(HttpMethod method, String... mvcPatterns) {
			return null;
		}

		@Override
		protected List<RequestMatcher> chainRequestMatchers(List<RequestMatcher> requestMatchers) {
			return requestMatchers;
		}

	}

}
