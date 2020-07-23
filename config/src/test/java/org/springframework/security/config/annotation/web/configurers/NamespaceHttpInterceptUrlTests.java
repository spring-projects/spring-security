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
package org.springframework.security.config.annotation.web.configurers;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests to verify that all the functionality of <intercept-url> attributes is present
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
public class NamespaceHttpInterceptUrlTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void unauthenticatedRequestWhenUrlRequiresAuthenticationThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HttpInterceptUrlConfig.class).autowire();

		this.mvc.perform(get("/users"))
				.andExpect(status().isForbidden());
	}

	@Test
	public void authenticatedRequestWhenUrlRequiresElevatedPrivilegesThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HttpInterceptUrlConfig.class).autowire();


		this.mvc.perform(get("/users")
				.with(authentication(user("ROLE_USER"))))
				.andExpect(status().isForbidden());
	}

	@Test
	public void authenticatedRequestWhenAuthorizedThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HttpInterceptUrlConfig.class, BaseController.class).autowire();

		this.mvc.perform(get("/users")
				.with(authentication(user("ROLE_ADMIN"))))
				.andExpect(status().isOk())
				.andReturn();
	}

	@Test
	public void requestWhenMappedByPostInterceptUrlThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HttpInterceptUrlConfig.class, BaseController.class).autowire();

		this.mvc.perform(get("/admin/post")
				.with(authentication(user("ROLE_USER"))))
				.andExpect(status().isOk());

		this.mvc.perform(post("/admin/post")
				.with(authentication(user("ROLE_USER"))))
				.andExpect(status().isForbidden());

		this.mvc.perform(post("/admin/post")
				.with(csrf())
				.with(authentication(user("ROLE_ADMIN"))))
				.andExpect(status().isOk());
	}

	@Test
	public void requestWhenRequiresChannelThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HttpInterceptUrlConfig.class).autowire();

		this.mvc.perform(get("/login"))
				.andExpect(redirectedUrl("https://localhost/login"));

		this.mvc.perform(get("/secured/a"))
				.andExpect(redirectedUrl("https://localhost/secured/a"));

		this.mvc.perform(get("https://localhost/user"))
				.andExpect(redirectedUrl("http://localhost/user"));
	}

	@EnableWebSecurity
	static class HttpInterceptUrlConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					// the line below is similar to intercept-url@pattern:
					//    <intercept-url pattern="/users**" access="hasRole('ROLE_ADMIN')"/>
					//    <intercept-url pattern="/sessions/**" access="hasRole('ROLE_ADMIN')"/>
					.antMatchers("/users**", "/sessions/**").hasRole("ADMIN")
					// the line below is similar to intercept-url@method:
					//    <intercept-url pattern="/admin/post" access="hasRole('ROLE_ADMIN')" method="POST"/>
					//    <intercept-url pattern="/admin/another-post/**" access="hasRole('ROLE_ADMIN')" method="POST"/>
					.antMatchers(HttpMethod.POST, "/admin/post", "/admin/another-post/**").hasRole("ADMIN")
					.antMatchers("/signup").permitAll()
					.anyRequest().hasRole("USER")
					.and()
				.requiresChannel()
					// NOTE: channel security is configured separately of authorization (i.e. intercept-url@access
					// the line below is similar to intercept-url@requires-channel="https":
					//    <intercept-url pattern="/login" requires-channel="https"/>
					//    <intercept-url pattern="/secured/**" requires-channel="https"/>
					.antMatchers("/login", "/secured/**").requiresSecure()
					// the line below is similar to intercept-url@requires-channel="http":
					//    <intercept-url pattern="/**" requires-channel="http"/>
					.anyRequest().requiresInsecure();
			// @formatter:on
		}

		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER").and()
					.withUser("admin").password("password").roles("USER", "ADMIN");
		}
	}

	@RestController
	static class BaseController {
		@GetMapping("/users")
		public String users() {
			return "ok";
		}

		@GetMapping("/sessions")
		public String sessions() {
			return "sessions";
		}

		@RequestMapping("/admin/post")
		public String adminPost() {
			return "adminPost";
		}

		@GetMapping("/admin/another-post")
		public String adminAnotherPost() {
			return "adminAnotherPost";
		}

		@GetMapping("/signup")
		public String signup() {
			return "signup";
		}
	}

	private static Authentication user(String role) {
		return new UsernamePasswordAuthenticationToken("user", null, AuthorityUtils.createAuthorityList(role));
	}

}
