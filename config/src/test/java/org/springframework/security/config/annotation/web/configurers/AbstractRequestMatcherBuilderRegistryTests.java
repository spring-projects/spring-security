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

package org.springframework.security.config.annotation.web.configurers;

import java.util.List;
import java.util.function.Consumer;

import jakarta.servlet.Servlet;
import jakarta.servlet.ServletContext;
import org.assertj.core.api.AbstractObjectAssert;
import org.assertj.core.api.ObjectAssert;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.MockServletContext;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link AbstractRequestMatcherBuilderRegistry}
 */
class AbstractRequestMatcherBuilderRegistryTests {

	@Test
	void defaultServletMatchersWhenDefaultDispatcherServletThenMvc() {
		MockServletContext servletContext = MockServletContext.mvc();
		List<RequestMatcher> matchers = defaultServlet(servletContext).requestMatchers("/mvc").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(MvcRequestMatcher.class);
		assertThatMvc(matchers).servletPath().isNull();
		assertThatMvc(matchers).pattern().isEqualTo("/mvc");
		assertThatMvc(matchers).method().isNull();
	}

	@Test
	void defaultServletHttpMethodMatchersWhenDefaultDispatcherServletThenMvc() {
		MockServletContext servletContext = MockServletContext.mvc();
		List<RequestMatcher> matchers = defaultServlet(servletContext).requestMatchers(HttpMethod.GET, "/mvc").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(MvcRequestMatcher.class);
		assertThatMvc(matchers).servletPath().isNull();
		assertThatMvc(matchers).pattern().isEqualTo("/mvc");
		assertThatMvc(matchers).method().isEqualTo(HttpMethod.GET);
	}

	@Test
	void servletMatchersWhenPathDispatcherServletThenMvc() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		List<RequestMatcher> matchers = servletPattern(servletContext, "/mvc/*")
			.requestMatchers("/controller").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(MvcRequestMatcher.class);
		assertThatMvc(matchers).servletPath().isEqualTo("/mvc");
		assertThatMvc(matchers).pattern().isEqualTo("/controller");
	}

	@Test
	void servletMatchersWhenAlsoExtraServletContainerMappingsThenMvc() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class);
		servletContext.addServlet("jspServlet", Servlet.class).addMapping("*.jsp", "*.jspx");
		servletContext.addServlet("facesServlet", Servlet.class).addMapping("/faces/", "*.jsf", "*.faces", "*.xhtml");
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		List<RequestMatcher> matchers = servletPattern(servletContext, "/mvc/*")
			.requestMatchers("/controller").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(MvcRequestMatcher.class);
		assertThatMvc(matchers).servletPath().isEqualTo("/mvc");
		assertThatMvc(matchers).pattern().isEqualTo("/controller");
	}

	@Test
	void defaultServletMatchersWhenOnlyDefaultServletThenAnt() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		List<RequestMatcher> matchers = defaultServlet(servletContext).requestMatchers("/controller").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(AntPathRequestMatcher.class);
		assertThatAnt(matchers).pattern().isEqualTo("/controller");
	}

	@Test
	void defaultDispatcherServletMatchersWhenNoHandlerMappingIntrospectorThenException() {
		MockServletContext servletContext = MockServletContext.mvc();
		assertThatExceptionOfType(NoSuchBeanDefinitionException.class)
			.isThrownBy(() -> defaultServlet(servletContext, (context) -> {
			}));
	}

	@Test
	void dispatcherServletMatchersWhenNoHandlerMappingIntrospectorThenException() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		assertThatExceptionOfType(NoSuchBeanDefinitionException.class)
			.isThrownBy(() -> servletPattern(servletContext, (context) -> {
			}, "/mvc/*"));
	}

	@Test
	void matchersWhenNoDispatchServletThenAnt() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		servletContext.addServlet("messageDispatcherServlet", Servlet.class).addMapping("/services/*");
		List<RequestMatcher> matchers = defaultServlet(servletContext).requestMatchers("/services/endpoint").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(AntPathRequestMatcher.class);
		assertThatAnt(matchers).pattern().isEqualTo("/services/endpoint");
	}

	@Test
	void servletMatchersWhenMixedServletsThenDeterminesByServletPath() {
		MockServletContext servletContext = MockServletContext.mvc();
		servletContext.addServlet("messageDispatcherServlet", Servlet.class).addMapping("/services/*");
		List<RequestMatcher> matchers = servletPattern(servletContext, "/services/*")
			.requestMatchers("/endpoint").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(AntPathRequestMatcher.class);
		assertThatAnt(matchers).pattern().isEqualTo("/services/endpoint");
		matchers = defaultServlet(servletContext).requestMatchers("/controller").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(MvcRequestMatcher.class);
		assertThatMvc(matchers).servletPath().isNull();
		assertThatMvc(matchers).pattern().isEqualTo("/controller");
	}

	@Test
	void servletMatchersWhenDispatcherServletNotDefaultThenDeterminesByServletPath() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		List<RequestMatcher> matchers = servletPattern(servletContext, "/mvc/*")
			.requestMatchers("/controller").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(MvcRequestMatcher.class);
		assertThatMvc(matchers).servletPath().isEqualTo("/mvc");
		assertThatMvc(matchers).pattern().isEqualTo("/controller");
		matchers = defaultServlet(servletContext).requestMatchers("/endpoint").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(AntPathRequestMatcher.class);
		assertThatAnt(matchers).pattern().isEqualTo("/endpoint");
	}

	@Test
	void servletHttpMatchersWhenDispatcherServletNotDefaultThenDeterminesByServletPath() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		List<RequestMatcher> matchers = servletPattern(servletContext, "/mvc/*").requestMatchers(HttpMethod.GET,
				"/controller").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(MvcRequestMatcher.class);
		assertThatMvc(matchers).method().isEqualTo(HttpMethod.GET);
		assertThatMvc(matchers).servletPath().isEqualTo("/mvc");
		assertThatMvc(matchers).pattern().isEqualTo("/controller");
		matchers = defaultServlet(servletContext).requestMatchers(HttpMethod.GET, "/endpoint").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(AntPathRequestMatcher.class);
		assertThatAnt(matchers).method().isEqualTo(HttpMethod.GET);
		assertThatAnt(matchers).pattern().isEqualTo("/endpoint");
	}

	@Test
	void servletMatchersWhenTwoDispatcherServletsThenDeterminesByServletPath() {
		MockServletContext servletContext = MockServletContext.mvc();
		servletContext.addServlet("two", DispatcherServlet.class).addMapping("/other/*");
		List<RequestMatcher> matchers = defaultServlet(servletContext).requestMatchers("/controller").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(MvcRequestMatcher.class);
		assertThatMvc(matchers).servletPath().isNull();
		assertThatMvc(matchers).pattern().isEqualTo("/controller");
		matchers = servletPattern(servletContext, "/other/*").requestMatchers("/endpoint").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(MvcRequestMatcher.class);
		assertThatMvc(matchers).servletPath().isEqualTo("/other");
		assertThatMvc(matchers).pattern().isEqualTo("/endpoint");
	}

	@Test
	void servletMatchersWhenMoreThanOneMappingThenDeterminesByServletPath() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/", "/two/*");
		List<RequestMatcher> matchers = defaultServlet(servletContext).requestMatchers("/controller").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(MvcRequestMatcher.class);
		assertThatMvc(matchers).servletPath().isNull();
		assertThatMvc(matchers).pattern().isEqualTo("/controller");
		matchers = servletPattern(servletContext, "/two/*").requestMatchers("/endpoint").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(MvcRequestMatcher.class);
		assertThatMvc(matchers).servletPath().isEqualTo("/two");
		assertThatMvc(matchers).pattern().isEqualTo("/endpoint");
	}

	@Test
	void servletMatchersWhenMoreThanOneMappingAndDefaultServletsThenDeterminesByServletPath() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/", "/two/*");
		servletContext.addServlet("jspServlet", Servlet.class).addMapping("*.jsp", "*.jspx");
		List<RequestMatcher> matchers = defaultServlet(servletContext).requestMatchers("/controller").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(MvcRequestMatcher.class);
		assertThatMvc(matchers).servletPath().isNull();
		assertThatMvc(matchers).pattern().isEqualTo("/controller");
		matchers = servletPattern(servletContext, "/two/*").requestMatchers("/endpoint").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(MvcRequestMatcher.class);
		assertThatMvc(matchers).servletPath().isEqualTo("/two");
		assertThatMvc(matchers).pattern().isEqualTo("/endpoint");
	}

	@Test
	void defaultServletWhenDispatcherServletThenMvc() {
		MockServletContext servletContext = MockServletContext.mvc();
		servletContext.addServlet("messageDispatcherServlet", Servlet.class).addMapping("/services/*");
		List<RequestMatcher> matchers = defaultServlet(servletContext).requestMatchers("/controller").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(MvcRequestMatcher.class);
		assertThatMvc(matchers).servletPath().isNull();
		assertThatMvc(matchers).pattern().isEqualTo("/controller");
		matchers = servletPattern(servletContext, "/services/*").requestMatchers("/endpoint").matchers;
		assertThat(matchers).hasSize(1).hasOnlyElementsOfType(AntPathRequestMatcher.class);
		assertThatAnt(matchers).pattern().isEqualTo("/services/endpoint");
	}

	@Test
	void defaultServletWhenNoDefaultServletThenException() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("messageDispatcherServlet", Servlet.class).addMapping("/services/*");
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> defaultServlet(servletContext));
	}

	@Test
	void servletPathWhenNoMatchingServletThenException() {
		MockServletContext servletContext = MockServletContext.mvc();
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> servletPattern(servletContext, "/wrong/*"));
	}

	TestServletRequestMatcherRegistry defaultServlet(ServletContext servletContext) {
		return servletPattern(servletContext, "/");
	}

	TestServletRequestMatcherRegistry defaultServlet(ServletContext servletContext,
			Consumer<GenericWebApplicationContext> consumer) {
		return servletPattern(servletContext, consumer, "/");
	}

	TestServletRequestMatcherRegistry servletPattern(ServletContext servletContext, String pattern) {
		return servletPattern(servletContext, (context) -> {
			context.registerBean("mvcHandlerMappingIntrospector", HandlerMappingIntrospector.class);
			context.registerBean(ObjectPostProcessor.class, () -> mock(ObjectPostProcessor.class));
		}, pattern);
	}

	TestServletRequestMatcherRegistry servletPattern(ServletContext servletContext,
			Consumer<GenericWebApplicationContext> consumer, String pattern) {
		GenericWebApplicationContext context = new GenericWebApplicationContext(servletContext);
		consumer.accept(context);
		context.refresh();
		return new TestServletRequestMatcherRegistry(context, pattern);
	}

	static MvcRequestMatcherAssert assertThatMvc(List<RequestMatcher> matchers) {
		RequestMatcher matcher = matchers.get(0);
		if (matcher instanceof AndRequestMatcher matching) {
			List<RequestMatcher> and = (List<RequestMatcher>) ReflectionTestUtils.getField(matching, "requestMatchers");
			assertThat(and).hasSize(2);
			assertThat(and.get(1)).isInstanceOf(MvcRequestMatcher.class);
			return new MvcRequestMatcherAssert((MvcRequestMatcher) and.get(1));
		}
		assertThat(matcher).isInstanceOf(MvcRequestMatcher.class);
		return new MvcRequestMatcherAssert((MvcRequestMatcher) matcher);
	}

	static AntPathRequestMatcherAssert assertThatAnt(List<RequestMatcher> matchers) {
		RequestMatcher matcher = matchers.get(0);
		if (matcher instanceof AndRequestMatcher matching) {
			List<RequestMatcher> and = (List<RequestMatcher>) ReflectionTestUtils.getField(matching, "requestMatchers");
			assertThat(and).hasSize(2);
			assertThat(and.get(1)).isInstanceOf(AntPathRequestMatcher.class);
			return new AntPathRequestMatcherAssert((AntPathRequestMatcher) and.get(1));
		}
		assertThat(matcher).isInstanceOf(AntPathRequestMatcher.class);
		return new AntPathRequestMatcherAssert((AntPathRequestMatcher) matcher);
	}

	static final class TestServletRequestMatcherRegistry
			extends AbstractRequestMatcherBuilderRegistry<TestServletRequestMatcherRegistry> {

		List<RequestMatcher> matchers;

		TestServletRequestMatcherRegistry(ApplicationContext context, String pattern) {
			super(context, RequestMatcherBuilders.createForServletPattern(context, pattern));
		}

		@Override
		protected TestServletRequestMatcherRegistry chainRequestMatchers(List<RequestMatcher> requestMatchers) {
			this.matchers = requestMatchers;
			return this;
		}

	}

	static final class MvcRequestMatcherAssert extends ObjectAssert<MvcRequestMatcher> {

		private MvcRequestMatcherAssert(MvcRequestMatcher matcher) {
			super(matcher);
		}

		AbstractObjectAssert<?, ?> servletPath() {
			return extracting("servletPath");
		}

		AbstractObjectAssert<?, ?> pattern() {
			return extracting("pattern");
		}

		AbstractObjectAssert<?, ?> method() {
			return extracting("method");
		}

	}

	static final class AntPathRequestMatcherAssert extends ObjectAssert<AntPathRequestMatcher> {

		private AntPathRequestMatcherAssert(AntPathRequestMatcher matcher) {
			super(matcher);
		}

		AbstractObjectAssert<?, ?> pattern() {
			return extracting("pattern");
		}

		AbstractObjectAssert<?, ?> method() {
			return extracting("httpMethod");
		}

	}

}
