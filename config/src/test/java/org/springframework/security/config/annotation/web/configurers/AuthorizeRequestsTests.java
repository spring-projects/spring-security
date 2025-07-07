/*
 * Copyright 2002-2024 the original author or authors.
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
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.servlet.MockServletContext;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.util.pattern.PathPatternParser;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.spy;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;

/**
 * @author Rob Winch
 *
 */
public class AuthorizeRequestsTests {

	AnnotationConfigWebApplicationContext context;

	MockHttpServletRequest request;

	MockHttpServletResponse response;

	MockFilterChain chain;

	MockServletContext servletContext;

	@Autowired
	FilterChainProxy springSecurityFilterChain;

	@BeforeEach
	public void setup() {
		this.servletContext = spy(MockServletContext.mvc());
		this.request = new MockHttpServletRequest(this.servletContext, "GET", "");
		this.response = new MockHttpServletResponse();
		this.chain = new MockFilterChain();
	}

	@AfterEach
	public void cleanup() {
		if (this.context != null) {
			this.context.close();
		}
	}

	// SEC-3135
	@Test
	public void antMatchersMethodAndNoPatterns() throws Exception {
		loadConfig(AntMatchersNoPatternsConfig.class);
		this.request.setMethod("POST");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
	}

	@Test
	public void postWhenPostDenyAllInLambdaThenRespondsWithForbidden() throws Exception {
		loadConfig(AntMatchersNoPatternsInLambdaConfig.class);
		this.request.setMethod("POST");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
	}

	// SEC-2256
	@Test
	public void antMatchersPathVariables() throws Exception {
		loadConfig(AntPatchersPathVariables.class);
		this.request.setServletPath("/user/user");
		this.request.setRequestURI("/user/user");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
		this.setup();
		this.request.setServletPath("/user/deny");
		this.request.setRequestURI("/user/deny");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
	}

	// SEC-2256
	@Test
	public void antMatchersPathVariablesCaseInsensitive() throws Exception {
		loadConfig(AntPatchersPathVariables.class);
		this.request.setRequestURI("/USER/user");
		this.request.setServletPath("/USER/user");
		this.request.setRequestURI("/USER/user");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
		this.setup();
		this.request.setRequestURI("/USER/deny");
		this.request.setServletPath("/USER/deny");
		this.request.setRequestURI("/USER/deny");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
	}

	// gh-3786
	@Test
	public void antMatchersPathVariablesCaseInsensitiveCamelCaseVariables() throws Exception {
		loadConfig(AntMatchersPathVariablesCamelCaseVariables.class);
		this.request.setServletPath("/USER/user");
		this.request.setRequestURI("/USER/user");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
		this.setup();
		this.request.setServletPath("/USER/deny");
		this.request.setRequestURI("/USER/deny");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
	}

	// gh-3394
	@Test
	public void roleHiearchy() throws Exception {
		loadConfig(RoleHiearchyConfig.class);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(UsernamePasswordAuthenticationToken.authenticated("test", "notused",
				AuthorityUtils.createAuthorityList("ROLE_USER")));
		this.request.getSession()
			.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
	}

	@Test
	public void mvcMatcherPathVariables() throws Exception {
		loadConfig(MvcMatcherPathVariablesConfig.class);
		this.request.setRequestURI("/user/user");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
		this.setup();
		this.request.setRequestURI("/user/deny");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
	}

	@Test
	public void requestWhenMvcMatcherPathVariablesThenMatchesOnPathVariables() throws Exception {
		loadConfig(MvcMatcherPathVariablesInLambdaConfig.class);
		this.request.setRequestURI("/user/user");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
		this.setup();
		this.request.setRequestURI("/user/deny");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
	}

	public void loadConfig(Class<?>... configs) {
		this.context = new AnnotationConfigWebApplicationContext();
		this.context.register(configs);
		this.context.setServletContext(this.servletContext);
		this.context.refresh();
		this.context.getAutowireCapableBeanFactory().autowireBean(this);
	}

	@EnableWebSecurity
	@Configuration
	static class AntMatchersNoPatternsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((requests) -> requests
					.requestMatchers(pathPattern(HttpMethod.POST, "/**")).denyAll());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

	}

	@EnableWebSecurity
	@Configuration
	static class AntMatchersNoPatternsInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorize) -> authorize
						.requestMatchers(pathPattern(HttpMethod.POST, "/**")).denyAll()
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

	}

	@EnableWebSecurity
	@Configuration
	static class AntPatchersPathVariables {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			PathPatternParser parser = new PathPatternParser();
			parser.setCaseSensitive(false);
			PathPatternRequestMatcher.Builder builder = PathPatternRequestMatcher.withPathPatternParser(parser);
			// @formatter:off
			http
				.authorizeRequests((requests) -> requests
					.requestMatchers(builder.matcher("/user/{user}")).access("#user == 'user'")
					.anyRequest().denyAll());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

	}

	@EnableWebSecurity
	@Configuration
	static class AntMatchersPathVariablesCamelCaseVariables {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			PathPatternParser parser = new PathPatternParser();
			parser.setCaseSensitive(false);
			PathPatternRequestMatcher.Builder builder = PathPatternRequestMatcher.withPathPatternParser(parser);
			// @formatter:off
			http
				.authorizeRequests((requests) -> requests
					.requestMatchers(builder.matcher("/user/{userName}")).access("#userName == 'user'")
					.anyRequest().denyAll());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

	}

	@EnableWebSecurity
	@Configuration
	static class RoleHiearchyConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((requests) -> requests
					.anyRequest().hasRole("ADMIN"));
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		RoleHierarchy roleHiearchy() {
			RoleHierarchyImpl result = new RoleHierarchyImpl();
			result.setHierarchy("ROLE_USER > ROLE_ADMIN");
			return result;
		}

	}

	@EnableWebSecurity
	@Configuration
	@EnableWebMvc
	static class MvcMatcherConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic(withDefaults())
				.authorizeRequests((requests) -> requests
					.requestMatchers("/path").denyAll());
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
	static class MvcMatcherInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic(withDefaults())
				.authorizeRequests((authorize) -> authorize
						.requestMatchers("/path").denyAll()
				);
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
	static class MvcMatcherServletPathConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http, PathPatternRequestMatcher.Builder builder) throws Exception {
			PathPatternRequestMatcher.Builder spring = builder.basePath("/spring");
			// @formatter:off
			http
				.httpBasic(withDefaults())
				.authorizeRequests((requests) -> requests
					.requestMatchers(spring.matcher("/path")).denyAll());
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
	static class MvcMatcherServletPathInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http, PathPatternRequestMatcher.Builder builder) throws Exception {
			PathPatternRequestMatcher.Builder spring = builder.basePath("/spring");
			// @formatter:off
			http
				.httpBasic(withDefaults())
				.authorizeRequests((authorize) -> authorize
						.requestMatchers(spring.matcher("/path")).denyAll()
				);
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
	static class MvcMatcherPathVariablesConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic(withDefaults())
				.authorizeRequests((requests) -> requests
					.requestMatchers("/user/{userName}").access("#userName == 'user'"));
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
	static class MvcMatcherPathVariablesInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic(withDefaults())
				.authorizeRequests((authorize) -> authorize
						.requestMatchers("/user/{userName}").access("#userName == 'user'")
				);
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
	static class MvcMatcherPathServletPathRequiredConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic(withDefaults())
				.authorizeRequests((requests) -> requests
					.requestMatchers("/user").denyAll());
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

}
