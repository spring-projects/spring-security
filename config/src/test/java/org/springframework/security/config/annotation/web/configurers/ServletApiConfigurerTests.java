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
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link ServletApiConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
public class ServletApiConfigurerTests {
	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnSecurityContextHolderAwareRequestFilter() {
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor)
				.postProcess(any(SecurityContextHolderAwareRequestFilter.class));
	}

	@EnableWebSecurity
	static class ObjectPostProcessorConfig extends WebSecurityConfigurerAdapter {
		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.servletApi();
			// @formatter:on
		}

		@Bean
		static ObjectPostProcessor<Object> objectPostProcessor() {
			return objectPostProcessor;
		}
	}

	static class ReflectingObjectPostProcessor implements ObjectPostProcessor<Object> {
		@Override
		public <O> O postProcess(O object) {
			return object;
		}
	}

	// SEC-2215
	@Test
	public void configureWhenUsingDefaultsThenAuthenticationManagerIsNotNull() {
		this.spring.register(ServletApiConfig.class).autowire();

		assertThat(this.spring.getContext().getBean("customAuthenticationManager")).isNotNull();
	}

	@Test
	public void configureWhenUsingDefaultsThenAuthenticationEntryPointIsLogin() throws Exception {
		this.spring.register(ServletApiConfig.class).autowire();

		this.mvc.perform(formLogin())
				.andExpect(status().isFound());
	}

	// SEC-2926
	@Test
	public void configureWhenUsingDefaultsThenRolePrefixIsSet() throws Exception {
		this.spring.register(ServletApiConfig.class, AdminController.class).autowire();

		this.mvc.perform(get("/admin")
				.with(authentication(new TestingAuthenticationToken("user", "pass", "ROLE_ADMIN"))))
				.andExpect(status().isOk());
	}

	@EnableWebSecurity
	static class ServletApiConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

		@Bean
		public AuthenticationManager customAuthenticationManager() throws Exception {
			return super.authenticationManagerBean();
		}
	}

	@Test
	public void requestWhenCustomAuthenticationEntryPointThenEntryPointUsed() throws Exception {
		this.spring.register(CustomEntryPointConfig.class).autowire();

		this.mvc.perform(get("/"));

		verify(CustomEntryPointConfig.ENTRYPOINT)
				.commence(any(HttpServletRequest.class),
						any(HttpServletResponse.class), any(AuthenticationException.class));
	}

	@EnableWebSecurity
	static class CustomEntryPointConfig extends WebSecurityConfigurerAdapter {
		static AuthenticationEntryPoint ENTRYPOINT = spy(AuthenticationEntryPoint.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.exceptionHandling()
					.authenticationEntryPoint(ENTRYPOINT)
					.and()
				.formLogin();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER");
			// @formatter:on
		}
	}

	@Test
	public void servletApiWhenInvokedTwiceThenUsesOriginalRole() throws Exception {
		this.spring.register(DuplicateInvocationsDoesNotOverrideConfig.class, AdminController.class).autowire();

		this.mvc.perform(get("/admin")
				.with(user("user").authorities(AuthorityUtils.createAuthorityList("PERMISSION_ADMIN"))))
				.andExpect(status().isOk());

		this.mvc.perform(get("/admin")
				.with(user("user").authorities(AuthorityUtils.createAuthorityList("ROLE_ADMIN"))))
				.andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class DuplicateInvocationsDoesNotOverrideConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.servletApi()
					.rolePrefix("PERMISSION_")
					.and()
				.servletApi();
			// @formatter:on
		}
	}

	@Test
	public void configureWhenSharedObjectTrustResolverThenTrustResolverUsed() throws Exception {
		this.spring.register(SharedTrustResolverConfig.class).autowire();

		this.mvc.perform(get("/"));

		verify(SharedTrustResolverConfig.TR, atLeastOnce()).isAnonymous(any());
	}

	@EnableWebSecurity
	static class SharedTrustResolverConfig extends WebSecurityConfigurerAdapter {
		static AuthenticationTrustResolver TR = spy(AuthenticationTrustResolver.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.setSharedObject(AuthenticationTrustResolver.class, TR);
			// @formatter:on
		}
	}

	@RestController
	static class AdminController {
		@GetMapping("/admin")
		public void admin(HttpServletRequest request) {
			if (!request.isUserInRole("ADMIN")) {
				throw new AccessDeniedException("This resource is only available to admins");
			}
		}
	}
}
