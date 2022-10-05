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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests to verify that all the functionality of &lt;intercept-url&gt; attributes is
 * present
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
@ExtendWith(SpringTestContextExtension.class)
public class NamespaceHttpInterceptUrlTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void unauthenticatedRequestWhenUrlRequiresAuthenticationThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HttpInterceptUrlConfig.class).autowire();
		this.mvc.perform(get("/users")).andExpect(status().isForbidden());
	}

	@Test
	public void authenticatedRequestWhenUrlRequiresElevatedPrivilegesThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HttpInterceptUrlConfig.class).autowire();
		MockHttpServletRequestBuilder requestWithUser = get("/users").with(authentication(user("ROLE_USER")));
		this.mvc.perform(requestWithUser).andExpect(status().isForbidden());
	}

	@Test
	public void authenticatedRequestWhenAuthorizedThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HttpInterceptUrlConfig.class, BaseController.class).autowire();
		MockHttpServletRequestBuilder requestWithAdmin = get("/users").with(authentication(user("ROLE_ADMIN")));
		this.mvc.perform(requestWithAdmin).andExpect(status().isOk()).andReturn();
	}

	@Test
	public void requestWhenMappedByPostInterceptUrlThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HttpInterceptUrlConfig.class, BaseController.class).autowire();
		MockHttpServletRequestBuilder getWithUser = get("/admin/post").with(authentication(user("ROLE_USER")));
		this.mvc.perform(getWithUser).andExpect(status().isOk());
		MockHttpServletRequestBuilder postWithUser = post("/admin/post").with(authentication(user("ROLE_USER")));
		this.mvc.perform(postWithUser).andExpect(status().isForbidden());
		MockHttpServletRequestBuilder requestWithAdmin = post("/admin/post").with(csrf())
				.with(authentication(user("ROLE_ADMIN")));
		this.mvc.perform(requestWithAdmin).andExpect(status().isOk());
	}

	@Test
	public void requestWhenRequiresChannelThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(HttpInterceptUrlConfig.class).autowire();
		this.mvc.perform(get("/login")).andExpect(redirectedUrl("https://localhost/login"));
		this.mvc.perform(get("/secured/a")).andExpect(redirectedUrl("https://localhost/secured/a"));
		this.mvc.perform(get("https://localhost/user")).andExpect(redirectedUrl("http://localhost/user"));
	}

	private static Authentication user(String role) {
		return UsernamePasswordAuthenticationToken.authenticated("user", null,
				AuthorityUtils.createAuthorityList(role));
	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class HttpInterceptUrlConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests().requestMatchers(
					// the line below is similar to intercept-url@pattern:
					//    <intercept-url pattern="/users**" access="hasRole('ROLE_ADMIN')"/>
					//" access="hasRole('ROLE_ADMIN')"/>
"/users**", "/sessions/**").hasRole("ADMIN").requestMatchers(
					// the line below is similar to intercept-url@method:
					//    <intercept-url pattern="/admin/post" access="hasRole('ROLE_ADMIN')" method="POST"/>
					//" access="hasRole('ROLE_ADMIN')" method="POST"/>
HttpMethod.POST, "/admin/post", "/admin/another-post/**").hasRole("ADMIN")
					.requestMatchers("/signup").permitAll()
					.anyRequest().hasRole("USER")
					.and()
				.requiresChannel().requestMatchers("/login", "/secured/**")
					// NOTE: channel security is configured separately of authorization (i.e. intercept-url@access
					// the line below is similar to intercept-url@requires-channel="https":
					//    <intercept-url pattern="/login" requires-channel="https"/>
					//" requires-channel="https"/>
				.requiresSecure().anyRequest().requiresInsecure();
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user(), PasswordEncodedUser.admin());
		}

	}

	@RestController
	static class BaseController {

		@GetMapping("/users")
		String users() {
			return "ok";
		}

		@GetMapping("/sessions")
		String sessions() {
			return "sessions";
		}

		@RequestMapping("/admin/post")
		String adminPost() {
			return "adminPost";
		}

		@GetMapping("/admin/another-post")
		String adminAnotherPost() {
			return "adminAnotherPost";
		}

		@GetMapping("/signup")
		String signup() {
			return "signup";
		}

	}

}
