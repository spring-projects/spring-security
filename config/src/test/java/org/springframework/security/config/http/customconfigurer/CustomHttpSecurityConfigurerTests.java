/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.http.customconfigurer;

import java.util.Properties;

import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.FilterChainProxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.config.http.customconfigurer.CustomConfigurer.customConfigurer;

/**
 * @author Rob Winch
 *
 */
public class CustomHttpSecurityConfigurerTests {

	@Autowired
	ConfigurableApplicationContext context;

	@Autowired
	FilterChainProxy springSecurityFilterChain;

	MockHttpServletRequest request;

	MockHttpServletResponse response;

	MockFilterChain chain;

	@Before
	public void setup() {
		request = new MockHttpServletRequest("GET", "");
		response = new MockHttpServletResponse();
		chain = new MockFilterChain();
		request.setMethod("GET");
	}

	@After
	public void cleanup() {
		if (context != null) {
			context.close();
		}
	}

	@Test
	public void customConfiguerPermitAll() throws Exception {
		loadContext(Config.class);

		request.setPathInfo("/public/something");

		springSecurityFilterChain.doFilter(request, response, chain);

		assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
	}

	@Test
	public void customConfiguerFormLogin() throws Exception {
		loadContext(Config.class);
		request.setPathInfo("/requires-authentication");

		springSecurityFilterChain.doFilter(request, response, chain);

		assertThat(response.getRedirectedUrl()).endsWith("/custom");
	}

	@Test
	public void customConfiguerCustomizeDisablesCsrf() throws Exception {
		loadContext(ConfigCustomize.class);
		request.setPathInfo("/public/something");
		request.setMethod("POST");

		springSecurityFilterChain.doFilter(request, response, chain);

		assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
	}

	@Test
	public void customConfiguerCustomizeFormLogin() throws Exception {
		loadContext(ConfigCustomize.class);
		request.setPathInfo("/requires-authentication");

		springSecurityFilterChain.doFilter(request, response, chain);

		assertThat(response.getRedirectedUrl()).endsWith("/other");
	}

	private void loadContext(Class<?> clazz) {
		AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(clazz);
		context.getAutowireCapableBeanFactory().autowireBean(this);
	}

	@EnableWebSecurity
	static class Config extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.apply(customConfigurer())
					.loginPage("/custom");
			// @formatter:on
		}

		@Bean
		public static PropertyPlaceholderConfigurer propertyPlaceholderConfigurer() {
			// Typically externalize this as a properties file
			Properties properties = new Properties();
			properties.setProperty("permitAllPattern", "/public/**");

			PropertyPlaceholderConfigurer propertyPlaceholderConfigurer = new PropertyPlaceholderConfigurer();
			propertyPlaceholderConfigurer.setProperties(properties);
			return propertyPlaceholderConfigurer;
		}

	}

	@EnableWebSecurity
	static class ConfigCustomize extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.apply(customConfigurer())
					.and()
				.csrf().disable()
				.formLogin()
					.loginPage("/other");
			// @formatter:on
		}

		@Bean
		public static PropertyPlaceholderConfigurer propertyPlaceholderConfigurer() {
			// Typically externalize this as a properties file
			Properties properties = new Properties();
			properties.setProperty("permitAllPattern", "/public/**");

			PropertyPlaceholderConfigurer propertyPlaceholderConfigurer = new PropertyPlaceholderConfigurer();
			propertyPlaceholderConfigurer.setProperties(properties);
			return propertyPlaceholderConfigurer;
		}

	}

}
