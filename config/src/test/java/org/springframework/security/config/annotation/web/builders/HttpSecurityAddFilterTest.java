/*
 * Copyright 2002-2020 the original author or authors.
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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.assertj.core.api.ListAssert;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;

import static org.assertj.core.api.Assertions.assertThat;

public class HttpSecurityAddFilterTest {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

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

	@EnableWebSecurity
	static class MyFilterMultipleAfterConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.addFilterAfter(new MyFilter(), WebAsyncManagerIntegrationFilter.class)
					.addFilterAfter(new MyFilter(), ExceptionTranslationFilter.class);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class MyFilterMultipleBeforeConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.addFilterBefore(new MyFilter(), WebAsyncManagerIntegrationFilter.class)
					.addFilterBefore(new MyFilter(), ExceptionTranslationFilter.class);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class MyFilterMultipleAtConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.addFilterAt(new MyFilter(), ChannelProcessingFilter.class)
					.addFilterAt(new MyFilter(), UsernamePasswordAuthenticationFilter.class);
			// @formatter:on
		}

	}

}
