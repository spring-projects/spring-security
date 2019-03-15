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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.spy;

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

	@Before
	public void setup() {
		this.servletContext = spy(new MockServletContext());
		this.request = new MockHttpServletRequest();
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

	// SEC-3135
	@Test
	public void antMatchersMethodAndNoPatterns() throws Exception {
		loadConfig(AntMatchersNoPatternsConfig.class);
		this.request.setMethod("POST");

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
	}

	@EnableWebSecurity
	@Configuration
	static class AntMatchersNoPatternsConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers(HttpMethod.POST).denyAll();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication();
			// @formatter:on
		}
	}

	// SEC-2256
	@Test
	public void antMatchersPathVariables() throws Exception {
		loadConfig(AntPatchersPathVariables.class);

		this.request.setServletPath("/user/user");

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);

		this.setup();
		this.request.setServletPath("/user/deny");

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
	}

	// SEC-2256
	@Test
	public void antMatchersPathVariablesCaseInsensitive() throws Exception {
		loadConfig(AntPatchersPathVariables.class);

		this.request.setServletPath("/USER/user");

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);

		this.setup();
		this.request.setServletPath("/USER/deny");

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
	}

	@EnableWebSecurity
	@Configuration
	static class AntPatchersPathVariables extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
				.requestMatchers(new AntPathRequestMatcher("/user/{user}", null, false)).access("#user == 'user'")
				.anyRequest().denyAll();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication();
			// @formatter:on
		}
	}

	// gh-3786
	@Test
	public void antMatchersPathVariablesCaseInsensitiveCamelCaseVariables() throws Exception {
		loadConfig(AntMatchersPathVariablesCamelCaseVariables.class);

		this.request.setServletPath("/USER/user");

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);

		this.setup();
		this.request.setServletPath("/USER/deny");

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
	}

	@EnableWebSecurity
	@Configuration
	static class AntMatchersPathVariablesCamelCaseVariables extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
				.requestMatchers(new AntPathRequestMatcher("/user/{userName}", null, false)).access("#userName == 'user'")
				.anyRequest().denyAll();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication();
			// @formatter:on
		}
	}

	// gh-3394
	@Test
	public void roleHiearchy() throws Exception {
		loadConfig(RoleHiearchyConfig.class);

		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new UsernamePasswordAuthenticationToken("test", "notused", AuthorityUtils.createAuthorityList("ROLE_USER")));
		this.request.getSession().setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
	}

	@EnableWebSecurity
	@Configuration
	static class RoleHiearchyConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("ADMIN");
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication();
			// @formatter:on
		}

		@Bean
		public RoleHierarchy roleHiearchy() {
			RoleHierarchyImpl result = new RoleHierarchyImpl();
			result.setHierarchy("ROLE_USER > ROLE_ADMIN");
			return result;
		}
	}

	@Test
	public void mvcMatcher() throws Exception {
		loadConfig(MvcMatcherConfig.class);

		this.request.setRequestURI("/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus())
				.isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);

		setup();

		this.request.setRequestURI("/path.html");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus())
				.isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);

		setup();

		this.request.setServletPath("/path/");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus())
				.isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
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
				.authorizeRequests()
					.mvcMatchers("/path").denyAll();
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

	@Test
	public void mvcMatcherServletPath() throws Exception {
		loadConfig(MvcMatcherServletPathConfig.class);

		this.request.setServletPath("/spring");
		this.request.setRequestURI("/spring/path");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus())
				.isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);

		setup();

		this.request.setServletPath("/spring");
		this.request.setRequestURI("/spring/path.html");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus())
				.isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);

		setup();

		this.request.setServletPath("/spring");
		this.request.setRequestURI("/spring/path/");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus())
				.isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);

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

	@EnableWebSecurity
	@Configuration
	@EnableWebMvc
	static class MvcMatcherServletPathConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic().and()
				.authorizeRequests()
					.mvcMatchers("/path").servletPath("/spring").denyAll();
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

	@Test
	public void mvcMatcherPathVariables() throws Exception {
		loadConfig(MvcMatcherPathVariablesConfig.class);

		this.request.setRequestURI("/user/user");

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);

		this.setup();
		this.request.setRequestURI("/user/deny");

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus())
				.isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
	}

	@EnableWebSecurity
	@Configuration
	@EnableWebMvc
	static class MvcMatcherPathVariablesConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic().and()
				.authorizeRequests()
					.mvcMatchers("/user/{userName}").access("#userName == 'user'");
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
	static class MvcMatcherPathServletPathRequiredConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic().and()
				.authorizeRequests()
					.mvcMatchers("/user").denyAll();
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

	public void loadConfig(Class<?>... configs) {
		this.context = new AnnotationConfigWebApplicationContext();
		this.context.register(configs);
		this.context.setServletContext(this.servletContext);
		this.context.refresh();

		this.context.getAutowireCapableBeanFactory().autowireBean(this);
	}
}
