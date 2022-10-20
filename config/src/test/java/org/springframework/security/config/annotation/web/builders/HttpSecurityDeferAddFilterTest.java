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

package org.springframework.security.config.annotation.web.builders;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.assertj.core.api.ListAssert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.header.HeaderWriterFilter;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringTestContextExtension.class)
public class HttpSecurityDeferAddFilterTest {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void addFilterAfterWhenSameFilterDifferentPlacesThenOrderCorrect() {
		this.spring.register(MyFilterMultipleAfterConfig.class).autowire();

		assertThatFilters().containsSubsequence(WebAsyncManagerIntegrationFilter.class, MyFilter.class,
				ExceptionTranslationFilter.class, MyFilter.class);
	}

	@Test
	public void addFilterBeforeWhenSameFilterDifferentPlacesThenOrderCorrect() {
		this.spring.register(MyFilterMultipleBeforeConfig.class).autowire();

		assertThatFilters().containsSubsequence(MyFilter.class, WebAsyncManagerIntegrationFilter.class, MyFilter.class,
				ExceptionTranslationFilter.class);
	}

	@Test
	public void addFilterAtWhenSameFilterDifferentPlacesThenOrderCorrect() {
		this.spring.register(MyFilterMultipleAtConfig.class).autowire();

		assertThatFilters().containsSubsequence(MyFilter.class, WebAsyncManagerIntegrationFilter.class, MyFilter.class,
				ExceptionTranslationFilter.class);
	}

	@Test
	public void addFilterAfterWhenAfterCustomFilterThenOrderCorrect() {
		this.spring.register(MyOtherFilterRelativeToMyFilterAfterConfig.class).autowire();

		assertThatFilters().containsSubsequence(WebAsyncManagerIntegrationFilter.class, MyFilter.class,
				MyOtherFilter.class);
	}

	@Test
	public void addFilterBeforeWhenBeforeCustomFilterThenOrderCorrect() {
		this.spring.register(MyOtherFilterRelativeToMyFilterBeforeConfig.class).autowire();

		assertThatFilters().containsSubsequence(MyOtherFilter.class, MyFilter.class,
				WebAsyncManagerIntegrationFilter.class);
	}

	@Test
	public void addFilterAtWhenAtCustomFilterThenOrderCorrect() {
		this.spring.register(MyOtherFilterRelativeToMyFilterAtConfig.class).autowire();

		assertThatFilters().containsSubsequence(WebAsyncManagerIntegrationFilter.class, MyFilter.class,
				MyOtherFilter.class, SecurityContextHolderFilter.class);
	}

	@Test
	public void addFilterBeforeWhenCustomFilterDifferentPlacesThenOrderCorrect() {
		this.spring.register(MyOtherFilterBeforeToMyFilterMultipleAfterConfig.class).autowire();

		assertThatFilters().containsSubsequence(WebAsyncManagerIntegrationFilter.class, MyOtherFilter.class,
				MyFilter.class, ExceptionTranslationFilter.class);
	}

	@Test
	public void addFilterBeforeAndAfterWhenCustomFiltersDifferentPlacesThenOrderCorrect() {
		this.spring.register(MyAnotherFilterRelativeToMyCustomFiltersMultipleConfig.class).autowire();

		assertThatFilters().containsSubsequence(HeaderWriterFilter.class, MyFilter.class, MyOtherFilter.class,
				MyOtherFilter.class, MyAnotherFilter.class, MyFilter.class, ExceptionTranslationFilter.class);
	}

	private ListAssert<Class<?>> assertThatFilters() {
		FilterChainProxy filterChain = this.spring.getContext().getBean(FilterChainProxy.class);
		List<Class<?>> filters = filterChain.getFilters("/").stream().map(Object::getClass)
				.collect(Collectors.toList());
		return assertThat(filters);
	}

	public static class MyFilter implements Filter {

		@Override
		public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
				throws IOException, ServletException {
			filterChain.doFilter(servletRequest, servletResponse);
		}

	}

	static class MyOtherFilter implements Filter {

		@Override
		public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
				throws IOException, ServletException {
			filterChain.doFilter(servletRequest, servletResponse);
		}

	}

	static class MyAnotherFilter implements Filter {

		@Override
		public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
				throws IOException, ServletException {
			filterChain.doFilter(servletRequest, servletResponse);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class MyFilterMultipleAfterConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.addFilterAfter(new MyFilter(), WebAsyncManagerIntegrationFilter.class)
					.addFilterAfter(new MyFilter(), ExceptionTranslationFilter.class);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class MyFilterMultipleBeforeConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.addFilterBefore(new MyFilter(), WebAsyncManagerIntegrationFilter.class)
					.addFilterBefore(new MyFilter(), ExceptionTranslationFilter.class);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class MyFilterMultipleAtConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.addFilterAt(new MyFilter(), ChannelProcessingFilter.class)
					.addFilterAt(new MyFilter(), UsernamePasswordAuthenticationFilter.class);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class MyOtherFilterRelativeToMyFilterAfterConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.addFilterAfter(new MyFilter(), WebAsyncManagerIntegrationFilter.class)
					.addFilterAfter(new MyOtherFilter(), MyFilter.class);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class MyOtherFilterRelativeToMyFilterBeforeConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.addFilterBefore(new MyFilter(), WebAsyncManagerIntegrationFilter.class)
					.addFilterBefore(new MyOtherFilter(), MyFilter.class);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class MyOtherFilterRelativeToMyFilterAtConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.addFilterAt(new MyFilter(), WebAsyncManagerIntegrationFilter.class)
					.addFilterAt(new MyOtherFilter(), MyFilter.class);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class MyOtherFilterBeforeToMyFilterMultipleAfterConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.addFilterAfter(new MyFilter(), WebAsyncManagerIntegrationFilter.class)
					.addFilterAfter(new MyFilter(), ExceptionTranslationFilter.class)
					.addFilterBefore(new MyOtherFilter(), MyFilter.class);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class MyAnotherFilterRelativeToMyCustomFiltersMultipleConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.addFilterAfter(new MyFilter(), HeaderWriterFilter.class)
					.addFilterBefore(new MyOtherFilter(), ExceptionTranslationFilter.class)
					.addFilterAfter(new MyOtherFilter(), MyFilter.class)
					.addFilterAt(new MyAnotherFilter(), MyOtherFilter.class)
					.addFilterAfter(new MyFilter(), MyAnotherFilter.class);
			// @formatter:on
			return http.build();
		}

	}

}
