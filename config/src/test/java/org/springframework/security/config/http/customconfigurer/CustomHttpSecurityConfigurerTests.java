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

package org.springframework.security.config.http.customconfigurer;

import java.util.Properties;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

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

	@BeforeEach
	public void setup() {
		this.request = new MockHttpServletRequest("GET", "");
		this.response = new MockHttpServletResponse();
		this.chain = new MockFilterChain();
		this.request.setMethod("GET");
	}

	@AfterEach
	public void cleanup() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	public void customConfiguerPermitAll() throws Exception {
		loadContext(Config.class);
		this.request.setPathInfo("/public/something");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
	}

	@Test
	public void customConfiguerFormLogin() throws Exception {
		loadContext(Config.class);
		this.request.setPathInfo("/requires-authentication");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getRedirectedUrl()).endsWith("/custom");
	}

	@Test
	public void customConfiguerCustomizeDisablesCsrf() throws Exception {
		loadContext(ConfigCustomize.class);
		this.request.setPathInfo("/public/something");
		this.request.setMethod("POST");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
	}

	@Test
	public void customConfiguerCustomizeFormLogin() throws Exception {
		loadContext(ConfigCustomize.class);
		this.request.setPathInfo("/requires-authentication");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getRedirectedUrl()).endsWith("/other");
	}

	private void loadContext(Class<?> clazz) {
		AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(clazz);
		context.getAutowireCapableBeanFactory().autowireBean(this);
	}

	@Configuration
	@EnableWebSecurity
	static class Config {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.apply(CustomConfigurer.customConfigurer())
					.loginPage("/custom");
			return http.build();
			// @formatter:on
		}

		@Bean
		static PropertyPlaceholderConfigurer propertyPlaceholderConfigurer() {
			// Typically externalize this as a properties file
			Properties properties = new Properties();
			properties.setProperty("permitAllPattern", "/public/**");
			PropertyPlaceholderConfigurer propertyPlaceholderConfigurer = new PropertyPlaceholderConfigurer();
			propertyPlaceholderConfigurer.setProperties(properties);
			return propertyPlaceholderConfigurer;
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ConfigCustomize {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.apply(CustomConfigurer.customConfigurer())
					.and()
				.csrf().disable()
				.formLogin()
					.loginPage("/other");
			return http.build();
			// @formatter:on
		}

		@Bean
		static PropertyPlaceholderConfigurer propertyPlaceholderConfigurer() {
			// Typically externalize this as a properties file
			Properties properties = new Properties();
			properties.setProperty("permitAllPattern", "/public/**");
			PropertyPlaceholderConfigurer propertyPlaceholderConfigurer = new PropertyPlaceholderConfigurer();
			propertyPlaceholderConfigurer.setProperties(properties);
			return propertyPlaceholderConfigurer;
		}

	}

}
