/*
 * Copyright 2002-2019 the original author or authors.
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

import org.junit.Test;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

/**
 * Tests for {@link AbstractRequestMatcherRegistry}.
 *
 * @author Ankur Pathak
 */
public class AbstractRequestMatcherRegistryAnyMatcherTests {

	@EnableWebSecurity
	static class AntMatchersAfterAnyRequestConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
				.anyRequest().authenticated()
				.antMatchers("/demo/**").permitAll();
			// @formatter:on

		}

	}

	@Test(expected = BeanCreationException.class)
	public void antMatchersCanNotWorkAfterAnyRequest() {
		loadConfig(AntMatchersAfterAnyRequestConfig.class);
	}

	@EnableWebSecurity
	static class MvcMatchersAfterAnyRequestConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
				.anyRequest().authenticated()
				.mvcMatchers("/demo/**").permitAll();
			// @formatter:on

		}

	}

	@Test(expected = BeanCreationException.class)
	public void mvcMatchersCanNotWorkAfterAnyRequest() {
		loadConfig(MvcMatchersAfterAnyRequestConfig.class);
	}

	@EnableWebSecurity
	static class RegexMatchersAfterAnyRequestConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
				.anyRequest().authenticated()
				.regexMatchers(".*").permitAll();
			// @formatter:on

		}

	}

	@Test(expected = BeanCreationException.class)
	public void regexMatchersCanNotWorkAfterAnyRequest() {
		loadConfig(RegexMatchersAfterAnyRequestConfig.class);
	}

	@EnableWebSecurity
	static class AnyRequestAfterItselfConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
				.anyRequest().authenticated()
				.anyRequest().permitAll();
			// @formatter:on

		}

	}

	@Test(expected = BeanCreationException.class)
	public void anyRequestCanNotWorkAfterItself() {
		loadConfig(AnyRequestAfterItselfConfig.class);
	}

	@EnableWebSecurity
	static class RequestMatchersAfterAnyRequestConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
				.anyRequest().authenticated()
				.requestMatchers(new AntPathRequestMatcher("/**")).permitAll();
			// @formatter:on

		}

	}

	@Test(expected = BeanCreationException.class)
	public void requestMatchersCanNotWorkAfterAnyRequest() {
		loadConfig(RequestMatchersAfterAnyRequestConfig.class);
	}

	private void loadConfig(Class<?>... configs) {
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.setAllowCircularReferences(false);
		context.register(configs);
		context.setServletContext(new MockServletContext());
		context.refresh();
	}

}
