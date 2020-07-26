/*
 * Copyright 2002-2015 the original author or authors.
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

import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @author M.S. Dousti
 *
 */
public class UrlAuthorizationConfigurerTests {

	AnnotationConfigWebApplicationContext context;

	MockHttpServletRequest request;

	MockHttpServletResponse response;

	MockFilterChain chain;

	@Autowired
	FilterChainProxy springSecurityFilterChain;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest("GET", "");
		this.request.setMethod("GET");
		this.response = new MockHttpServletResponse();
		this.chain = new MockFilterChain();
	}

	@After
	public void cleanup() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	public void mvcMatcher() throws Exception {
		loadConfig(MvcMatcherConfig.class, LegacyMvcMatchingConfig.class);

		this.request.setRequestURI("/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);

		setup();

		this.request.setRequestURI("/path.html");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);

		setup();

		this.request.setServletPath("/path/");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
	}

	@Test
	public void mvcMatcherServletPath() throws Exception {
		loadConfig(MvcMatcherServletPathConfig.class, LegacyMvcMatchingConfig.class);

		this.request.setServletPath("/spring");
		this.request.setRequestURI("/spring/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);

		setup();

		this.request.setServletPath("/spring");
		this.request.setRequestURI("/spring/path.html");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);

		setup();

		this.request.setServletPath("/spring");
		this.request.setRequestURI("/spring/path/");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);

		setup();

		this.request.setServletPath("/foo");
		this.request.setRequestURI("/foo/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);

		setup();

		this.request.setServletPath("/");
		this.request.setRequestURI("/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
	}

	@Test
	public void anonymousUrlAuthorization() {
		loadConfig(AnonymousUrlAuthorizationConfig.class);
	}

	public void loadConfig(Class<?>... configs) {
		this.context = new AnnotationConfigWebApplicationContext();
		this.context.register(configs);
		this.context.setServletContext(new MockServletContext());
		this.context.refresh();

		this.context.getAutowireCapableBeanFactory().autowireBean(this);
	}

	@EnableWebSecurity
	@Configuration
	@EnableWebMvc
	static class MvcMatcherConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic().and()
				.apply(new UrlAuthorizationConfigurer(getApplicationContext())).getRegistry()
					.mvcMatchers("/path").hasRole("ADMIN");
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication();
			// @formatter:on
		}

		@RestController
		static class PathController {

			@RequestMapping("/path")
			public String path() {
				return "path";
			}

		}

	}

	@EnableWebSecurity
	@Configuration
	@EnableWebMvc
	static class MvcMatcherServletPathConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic().and()
				.apply(new UrlAuthorizationConfigurer(getApplicationContext())).getRegistry()
					.mvcMatchers("/path").servletPath("/spring").hasRole("ADMIN");
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication();
			// @formatter:on
		}

		@RestController
		static class PathController {

			@RequestMapping("/path")
			public String path() {
				return "path";
			}

		}

	}

	@EnableWebSecurity
	@Configuration
	static class AnonymousUrlAuthorizationConfig extends WebSecurityConfigurerAdapter {

		@Override
		public void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.apply(new UrlAuthorizationConfigurer<>(null)).getRegistry()
					.anyRequest().anonymous();
			// @formatter:on
		}

	}

	@Configuration
	static class LegacyMvcMatchingConfig implements WebMvcConfigurer {

		@Override
		public void configurePathMatch(PathMatchConfigurer configurer) {
			configurer.setUseSuffixPatternMatch(true);
		}

	}

}
