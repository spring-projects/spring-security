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

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
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
import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author Rob Winch
 *
 */
public class HttpSecurityRequestMatchersTests {

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
		this.request.setServletPath("/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
		setup();
		this.request.setServletPath("/path.html");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
		setup();
		this.request.setServletPath("/path/");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
	}

	@Test
	public void mvcMatcherGetFiltersNoUnsupportedMethodExceptionFromDummyRequest() {
		loadConfig(MvcMatcherConfig.class);
		assertThat(this.springSecurityFilterChain.getFilters("/path")).isNotEmpty();
	}

	@Test
	public void requestMatchersMvcMatcher() throws Exception {
		loadConfig(RequestMatchersMvcMatcherConfig.class, LegacyMvcMatchingConfig.class);
		this.request.setServletPath("/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
		setup();
		this.request.setServletPath("/path.html");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
		setup();
		this.request.setServletPath("/path/");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
	}

	@Test
	public void requestMatchersWhenMvcMatcherInLambdaThenPathIsSecured() throws Exception {
		loadConfig(RequestMatchersMvcMatcherInLambdaConfig.class, LegacyMvcMatchingConfig.class);
		this.request.setServletPath("/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
		setup();
		this.request.setServletPath("/path.html");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
		setup();
		this.request.setServletPath("/path/");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
	}

	@Test
	public void requestMatchersMvcMatcherServletPath() throws Exception {
		loadConfig(RequestMatchersMvcMatcherServeltPathConfig.class);
		this.request.setServletPath("/spring");
		this.request.setRequestURI("/spring/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
		setup();
		this.request.setServletPath("");
		this.request.setRequestURI("/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
		setup();
		this.request.setServletPath("/other");
		this.request.setRequestURI("/other/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
	}

	@Test
	public void requestMatcherWhensMvcMatcherServletPathInLambdaThenPathIsSecured() throws Exception {
		loadConfig(RequestMatchersMvcMatcherServletPathInLambdaConfig.class);
		this.request.setServletPath("/spring");
		this.request.setRequestURI("/spring/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
		setup();
		this.request.setServletPath("");
		this.request.setRequestURI("/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
		setup();
		this.request.setServletPath("/other");
		this.request.setRequestURI("/other/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
	}

	@Test
	public void requestMatcherWhenMultiMvcMatcherInLambdaThenAllPathsAreDenied() throws Exception {
		loadConfig(MultiMvcMatcherInLambdaConfig.class);
		this.request.setRequestURI("/test-1");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
		setup();
		this.request.setRequestURI("/test-2");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
		setup();
		this.request.setRequestURI("/test-3");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
	}

	@Test
	public void requestMatcherWhenMultiMvcMatcherThenAllPathsAreDenied() throws Exception {
		loadConfig(MultiMvcMatcherConfig.class);
		this.request.setRequestURI("/test-1");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
		setup();
		this.request.setRequestURI("/test-2");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
		setup();
		this.request.setRequestURI("/test-3");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
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
	static class MultiMvcMatcherInLambdaConfig {

		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE)
		SecurityFilterChain first(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
			MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
			// @formatter:off
			http
				.securityMatchers((requests) -> requests
					.requestMatchers(mvcMatcherBuilder.pattern("/test-1"))
					.requestMatchers(mvcMatcherBuilder.pattern("/test-2"))
					.requestMatchers(mvcMatcherBuilder.pattern("/test-3"))
				)
				.authorizeRequests((authorize) -> authorize.anyRequest().denyAll())
				.httpBasic(withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		SecurityFilterChain second(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
			MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
			// @formatter:off
			http
				.securityMatchers((requests) -> requests
					.requestMatchers(mvcMatcherBuilder.pattern("/test-1"))
				)
				.authorizeRequests((authorize) -> authorize
					.anyRequest().permitAll()
				);
			// @formatter:on
			return http.build();
		}

		@RestController
		static class PathController {

			@RequestMapping({ "/test-1", "/test-2", "/test-3" })
			String path() {
				return "path";
			}

		}

	}

	@EnableWebSecurity
	@Configuration
	@EnableWebMvc
	static class MultiMvcMatcherConfig {

		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE)
		SecurityFilterChain first(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
			MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
			// @formatter:off
			http
				.securityMatchers()
					.requestMatchers(mvcMatcherBuilder.pattern("/test-1"))
					.requestMatchers(mvcMatcherBuilder.pattern("/test-2"))
					.requestMatchers(mvcMatcherBuilder.pattern("/test-3"))
					.and()
				.authorizeRequests()
					.anyRequest().denyAll()
					.and()
				.httpBasic(withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		SecurityFilterChain second(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
			MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
			// @formatter:off
			http
				.securityMatchers()
					.requestMatchers(mvcMatcherBuilder.pattern("/test-1"))
					.and()
				.authorizeRequests()
					.anyRequest().permitAll();
			// @formatter:on
			return http.build();
		}

		@RestController
		static class PathController {

			@RequestMapping({ "/test-1", "/test-2", "/test-3" })
			String path() {
				return "path";
			}

		}

	}

	@EnableWebSecurity
	@Configuration
	@EnableWebMvc
	static class MvcMatcherConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
			// @formatter:off
			http
				.securityMatcher(new MvcRequestMatcher(introspector, "/path"))
				.httpBasic().and()
				.authorizeRequests()
					.anyRequest().denyAll();
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
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
	static class RequestMatchersMvcMatcherConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
			// @formatter:off
			http
				.securityMatchers()
					.requestMatchers(new MvcRequestMatcher(introspector, "/path"))
					.and()
				.httpBasic().and()
				.authorizeRequests()
					.anyRequest().denyAll();
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
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
	static class RequestMatchersMvcMatcherInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
			// @formatter:off
			http
				.securityMatchers((matchers) ->
					matchers
						.requestMatchers(new MvcRequestMatcher(introspector, "/path"))
				)
				.httpBasic(withDefaults())
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().denyAll()
				);
			return http.build();
			// @formatter:on
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
	static class RequestMatchersMvcMatcherServeltPathConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
			MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
			mvcMatcherBuilder.servletPath("/spring");
			// @formatter:off
			http
				.securityMatchers()
					.requestMatchers(mvcMatcherBuilder.pattern("/path"))
					.requestMatchers("/never-match")
					.and()
				.httpBasic().and()
				.authorizeRequests()
					.anyRequest().denyAll();
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
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
	static class RequestMatchersMvcMatcherServletPathInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
			MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
			mvcMatcherBuilder.servletPath("/spring");
			// @formatter:off
			http
				.securityMatchers((matchers) ->
					matchers
						.requestMatchers(mvcMatcherBuilder.pattern("/path"))
						.requestMatchers("/never-match")
				)
				.httpBasic(withDefaults())
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().denyAll()
				);
			return http.build();
			// @formatter:on
		}

		@RestController
		static class PathController {

			@RequestMapping("/path")
			String path() {
				return "path";
			}

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

}
