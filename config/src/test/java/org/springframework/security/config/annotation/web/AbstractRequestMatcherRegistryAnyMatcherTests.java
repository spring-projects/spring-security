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

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.web.PathPatternRequestMatcherBuilderFactoryBean;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link AbstractRequestMatcherRegistry}.
 *
 * @author Ankur Pathak
 */
public class AbstractRequestMatcherRegistryAnyMatcherTests {

	@Test
	public void antMatchersCanNotWorkAfterAnyRequest() {
		assertThatExceptionOfType(BeanCreationException.class)
			.isThrownBy(() -> loadConfig(AntMatchersAfterAnyRequestConfig.class));
	}

	@Test
	public void mvcMatchersCanNotWorkAfterAnyRequest() {
		assertThatExceptionOfType(BeanCreationException.class)
			.isThrownBy(() -> loadConfig(MvcMatchersAfterAnyRequestConfig.class));
	}

	@Test
	public void regexMatchersCanNotWorkAfterAnyRequest() {
		assertThatExceptionOfType(BeanCreationException.class)
			.isThrownBy(() -> loadConfig(RegexMatchersAfterAnyRequestConfig.class));
	}

	@Test
	public void anyRequestCanNotWorkAfterItself() {
		assertThatExceptionOfType(BeanCreationException.class)
			.isThrownBy(() -> loadConfig(AnyRequestAfterItselfConfig.class));
	}

	@Test
	public void requestMatchersCanNotWorkAfterAnyRequest() {
		assertThatExceptionOfType(BeanCreationException.class)
			.isThrownBy(() -> loadConfig(RequestMatchersAfterAnyRequestConfig.class));
	}

	private void loadConfig(Class<?>... configs) {
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.setAllowCircularReferences(false);
		context.register(configs);
		context.setServletContext(new MockServletContext());
		context.refresh();
	}

	@Configuration
	@EnableWebSecurity
	static class AntMatchersAfterAnyRequestConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((requests) -> requests
					.anyRequest().authenticated()
					.requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/demo/**")).permitAll());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class MvcMatchersAfterAnyRequestConfig {

		@Bean
		PathPatternRequestMatcherBuilderFactoryBean pathPattern() {
			return new PathPatternRequestMatcherBuilderFactoryBean();
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http, PathPatternRequestMatcher.Builder builder) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((requests) -> requests
					.anyRequest().authenticated()
					.requestMatchers(builder.matcher("/demo/**")).permitAll());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RegexMatchersAfterAnyRequestConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((requests) -> requests
					.anyRequest().authenticated()
					.requestMatchers(new RegexRequestMatcher(".*", null)).permitAll());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AnyRequestAfterItselfConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((requests) -> requests
					.anyRequest().authenticated()
					.anyRequest().permitAll());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RequestMatchersAfterAnyRequestConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((requests) -> requests
					.anyRequest().authenticated()
					.requestMatchers(PathPatternRequestMatcher.withDefaults().matcher("/**")).permitAll());
			return http.build();
			// @formatter:on
		}

	}

}
