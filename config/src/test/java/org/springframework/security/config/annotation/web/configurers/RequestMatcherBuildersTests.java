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
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.MockServletContext;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.configurers.DispatcherServletDelegatingRequestMatcherBuilder.DispatcherServletDelegatingRequestMatcher;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

public class RequestMatcherBuildersTests {

	@Test
	void matchersWhenDefaultDispatcherServletThenMvc() {
		MockServletContext servletContext = MockServletContext.mvc();
		RequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		List<RequestMatcher> matchers = builder.matchers("/mvc");
		assertThat(matchers.get(0)).isInstanceOf(MvcRequestMatcher.class);
		MvcRequestMatcher matcher = (MvcRequestMatcher) matchers.get(0);
		assertThat(ReflectionTestUtils.getField(matcher, "servletPath")).isNull();
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/mvc");
	}

	@Test
	void httpMethodMatchersWhenDefaultDispatcherServletThenMvc() {
		MockServletContext servletContext = MockServletContext.mvc();
		RequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		List<RequestMatcher> matchers = builder.matchers(HttpMethod.GET, "/mvc");
		assertThat(matchers.get(0)).isInstanceOf(MvcRequestMatcher.class);
		MvcRequestMatcher matcher = (MvcRequestMatcher) matchers.get(0);
		assertThat(ReflectionTestUtils.getField(matcher, "servletPath")).isNull();
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/mvc");
		assertThat(ReflectionTestUtils.getField(matcher, "method")).isEqualTo(HttpMethod.GET);
	}

	@Test
	void matchersWhenPathDispatcherServletThenMvc() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		RequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		List<RequestMatcher> matchers = builder.matchers("/controller");
		assertThat(matchers.get(0)).isInstanceOf(MvcRequestMatcher.class);
		MvcRequestMatcher matcher = (MvcRequestMatcher) matchers.get(0);
		assertThat(ReflectionTestUtils.getField(matcher, "servletPath")).isEqualTo("/mvc");
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/controller");
	}

	@Test
	void matchersWhenAlsoExtraServletContainerMappingsThenRequiresServletPath() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		servletContext.addServlet("jspServlet", Servlet.class).addMapping("*.jsp", "*.jspx");
		servletContext.addServlet("facesServlet", Servlet.class).addMapping("/faces/", "*.jsf", "*.faces", "*.xhtml");
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> requestMatchersBuilder(servletContext).matcher("/path"))
			.withMessageContaining(".forServletPattern");
	}

	@Test
	void matchersWhenOnlyDefaultServletThenAnt() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		RequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		List<RequestMatcher> matchers = builder.matchers("/controller");
		assertThat(matchers.get(0)).isInstanceOf(AntPathRequestMatcher.class);
		AntPathRequestMatcher matcher = (AntPathRequestMatcher) matchers.get(0);
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/controller");
	}

	@Test
	void matchersWhenNoHandlerMappingIntrospectorThenAnt() {
		MockServletContext servletContext = MockServletContext.mvc();
		RequestMatcherBuilder builder = requestMatchersBuilder(servletContext, (context) -> {
		});
		List<RequestMatcher> matchers = builder.matchers("/controller");
		assertThat(matchers.get(0)).isInstanceOf(AntPathRequestMatcher.class);
		AntPathRequestMatcher matcher = (AntPathRequestMatcher) matchers.get(0);
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/controller");
	}

	@Test
	void matchersWhenNoDispatchServletThenAnt() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		servletContext.addServlet("messageDispatcherServlet", Servlet.class).addMapping("/services/*");
		RequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		List<RequestMatcher> matchers = builder.matchers("/services/endpoint");
		assertThat(matchers.get(0)).isInstanceOf(AntPathRequestMatcher.class);
		AntPathRequestMatcher matcher = (AntPathRequestMatcher) matchers.get(0);
		assertThat(ReflectionTestUtils.getField(matcher, "pattern")).isEqualTo("/services/endpoint");
	}

	@Test
	void matchersWhenMixedServletsThenServletPathDelegating() {
		MockServletContext servletContext = MockServletContext.mvc();
		servletContext.addServlet("messageDispatcherServlet", Servlet.class).addMapping("/services/*");
		RequestMatcherBuilder builder = requestMatchersBuilder(servletContext);
		assertThat(builder.matchers("/services/endpoint").get(0))
			.isInstanceOf(DispatcherServletDelegatingRequestMatcher.class);
	}

	@Test
	void matchersWhenDispatcherServletNotDefaultAndOtherServletsThenRequiresServletPath() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> requestMatchersBuilder(servletContext).matcher("/path/**"))
			.withMessageContaining(".forServletPattern");
	}

	@Test
	void httpMatchersWhenDispatcherServletNotDefaultAndOtherServletsThenRequiresServletPath() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("default", Servlet.class).addMapping("/");
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/mvc/*");
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> requestMatchersBuilder(servletContext).matcher("/pattern"))
			.withMessageContaining(".forServletPattern");
	}

	@Test
	void matchersWhenTwoDispatcherServletsThenException() {
		MockServletContext servletContext = MockServletContext.mvc();
		servletContext.addServlet("two", DispatcherServlet.class).addMapping("/other/*");
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> requestMatchersBuilder(servletContext).matcher("/path/**"))
			.withMessageContaining(".forServletPattern");
	}

	@Test
	void matchersWhenMoreThanOneMappingThenException() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/", "/two/*");
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> requestMatchersBuilder(servletContext).matcher("/path/**"))
			.withMessageContaining(".forServletPattern");
	}

	@Test
	void matchersWhenMoreThanOneMappingAndDefaultServletsThenRequiresServletPath() {
		MockServletContext servletContext = new MockServletContext();
		servletContext.addServlet("dispatcherServlet", DispatcherServlet.class).addMapping("/", "/two/*");
		servletContext.addServlet("jspServlet", Servlet.class).addMapping("*.jsp", "*.jspx");
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> requestMatchersBuilder(servletContext).matcher("/path/**"))
			.withMessageContaining(".forServletPattern");
	}

	RequestMatcherBuilder requestMatchersBuilder(ServletContext servletContext) {
		return requestMatchersBuilder(servletContext, (context) -> {
			context.registerBean("mvcHandlerMappingIntrospector", HandlerMappingIntrospector.class,
					() -> mock(HandlerMappingIntrospector.class));
			context.registerBean(ObjectPostProcessor.class, () -> mock(ObjectPostProcessor.class));
		});
	}

	RequestMatcherBuilder requestMatchersBuilder(ServletContext servletContext,
			Consumer<GenericWebApplicationContext> consumer) {
		GenericWebApplicationContext context = new GenericWebApplicationContext(servletContext);
		consumer.accept(context);
		context.refresh();
		return RequestMatcherBuilders.createDefault(context);
	}

}
