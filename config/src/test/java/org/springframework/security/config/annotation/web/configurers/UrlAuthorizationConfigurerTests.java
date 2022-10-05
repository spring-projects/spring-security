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

package org.springframework.security.config.annotation.web.configurers;

import java.util.Base64;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

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

	@BeforeEach
	public void setup() {
		this.request = new MockHttpServletRequest("GET", "");
		this.request.setMethod("GET");
		this.response = new MockHttpServletResponse();
		this.chain = new MockFilterChain();
	}

	@AfterEach
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

	// gh-10956
	@Test
	public void multiMvcMatchersConfig() throws Exception {
		loadConfig(MultiMvcMatcherConfig.class);
		this.request.addHeader("Authorization",
				"Basic " + new String(Base64.getEncoder().encode("user:password".getBytes())));
		this.request.setRequestURI("/test-1");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
		setup();
		this.request.addHeader("Authorization",
				"Basic " + new String(Base64.getEncoder().encode("user:password".getBytes())));
		this.request.setRequestURI("/test-2");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
		setup();
		this.request.addHeader("Authorization",
				"Basic " + new String(Base64.getEncoder().encode("user:password".getBytes())));
		this.request.setRequestURI("/test-3");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
		setup();
		this.request.addHeader("Authorization",
				"Basic " + new String(Base64.getEncoder().encode("user:password".getBytes())));
		this.request.setRequestURI("/test-x");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
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
	static class MvcMatcherConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http, ApplicationContext context,
				HandlerMappingIntrospector introspector) throws Exception {
			// @formatter:off
			http
				.httpBasic().and()
				.apply(new UrlAuthorizationConfigurer(context)).getRegistry()
					.requestMatchers(new MvcRequestMatcher(introspector, "/path")).hasRole("ADMIN");
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

		@RestController
		static class PathController {

			@RequestMapping("/path")
			String path() {
				return "path";
			}

		}

	}

	@EnableWebSecurity
	@Configuration
	@EnableWebMvc
	static class MvcMatcherServletPathConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http, ApplicationContext context,
				HandlerMappingIntrospector introspector) throws Exception {
			MvcRequestMatcher mvcRequestMatcher = new MvcRequestMatcher(introspector, "/path");
			mvcRequestMatcher.setServletPath("/spring");
			// @formatter:off
			http
				.httpBasic().and()
				.apply(new UrlAuthorizationConfigurer(context)).getRegistry()
					.requestMatchers(mvcRequestMatcher).hasRole("ADMIN");
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

		@RestController
		static class PathController {

			@RequestMapping("/path")
			String path() {
				return "path";
			}

		}

	}

	@EnableWebSecurity
	@Configuration
	static class AnonymousUrlAuthorizationConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.apply(new UrlAuthorizationConfigurer<>(null)).getRegistry()
					.anyRequest().anonymous();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	static class LegacyMvcMatchingConfig implements WebMvcConfigurer {

		@Override
		public void configurePathMatch(PathMatchConfigurer configurer) {
			configurer.setUseSuffixPatternMatch(true);
			configurer.setUseTrailingSlashMatch(true);
		}

	}

	@EnableWebSecurity
	@Configuration
	@EnableWebMvc
	static class MultiMvcMatcherConfig {

		@Bean
		SecurityFilterChain security(HttpSecurity http, ApplicationContext context) throws Exception {
			// @formatter:off
			http
					.httpBasic(Customizer.withDefaults())
					.apply(new UrlAuthorizationConfigurer<>(context)).getRegistry()
						.requestMatchers("/test-1").hasRole("ADMIN")
						.requestMatchers("/test-2").hasRole("ADMIN")
						.requestMatchers("/test-3").hasRole("ADMIN")
						.anyRequest().hasRole("USER");
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER")
					.build();
			return new InMemoryUserDetailsManager(user);
		}

		@RestController
		static class PathController {

			@RequestMapping({ "/test-1", "/test-2", "/test-3", "/test-x" })
			String path() {
				return "path";
			}

		}

	}

}
