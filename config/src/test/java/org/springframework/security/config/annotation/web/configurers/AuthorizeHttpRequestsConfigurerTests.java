/*
 * Copyright 2002-2021 the original author or authors.
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

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.DelegatingAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link AuthorizeHttpRequestsConfigurer}.
 *
 * @author Evgeniy Cheban
 */
public class AuthorizeHttpRequestsConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenAuthorizedHttpRequestsAndNoRequestsThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(NoRequestsConfig.class).autowire()).withMessageContaining(
						"At least one mapping is required (for example, authorizeHttpRequests().anyRequest().authenticated())");
	}

	@Test
	public void configureWhenAuthorizedHttpRequestsAndNoRequestsThenExceptionWithDefaultConfig() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(NoRequestsConfigWithDefaultConfig.class).autowire())
				.withMessageContaining(
						"At least one mapping is required (for example, authorizeHttpRequests().anyRequest().authenticated())");
	}

	@Test
	public void configureWhenAnyRequestIncompleteMappingThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(IncompleteMappingConfig.class).autowire())
				.withMessageContaining("An incomplete mapping was found for ");
	}

	@Test
	public void configureWhenAnyRequestIncompleteMappingDefaultConfigThenException() {
		// assertThatExceptionOfType(BeanCreationException.class)
		// .isThrownBy(() ->
		// .withMessageContaining("An incomplete mapping was found for ");
		CustomAuthorizationManagerConfig.authorizationManager = mock(AuthorizationManager.class);
		this.spring.register(IncompleteMappingConfigWithDefaultConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isOk());
		verify(CustomAuthorizationManagerConfig.authorizationManager).check(any(), any());
	}

	@Test
	public void configureWhenMvcMatcherAfterAnyRequestThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(AfterAnyRequestConfig.class).autowire())
				.withMessageContaining("Can't configure mvcMatchers after anyRequest");
	}

	@Test
	public void configureMvcMatcherAccessAuthorizationManagerWhenNotNullThenVerifyUse() throws Exception {
		CustomAuthorizationManagerConfig.authorizationManager = mock(AuthorizationManager.class);
		this.spring.register(CustomAuthorizationManagerConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isOk());
		verify(CustomAuthorizationManagerConfig.authorizationManager).check(any(), any());
	}

	@Test
	public void configureMvcMatcherAccessAuthorizationManagerOnDefault() throws Exception {
		CustomAuthorizationManagerConfig.authorizationManager = mock(AuthorizationManager.class);
		this.spring.register(IncompleteMappingConfigWithDefaultConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isOk());
		verify(CustomAuthorizationManagerConfig.authorizationManager).check(any(), any());
	}

	@Test
	public void configureMvcMatcherAccessAuthorizationManagerWhenNullThenException() {
		CustomAuthorizationManagerConfig.authorizationManager = null;
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(CustomAuthorizationManagerConfig.class).autowire())
				.withMessageContaining("manager cannot be null");
	}

	@Test
	public void configureWhenObjectPostProcessorRegisteredThenInvokedOnAuthorizationManagerAndAuthorizationFilter() {
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(DelegatingAuthorizationManager.class));
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(AuthorizationFilter.class));
	}

	@Test
	public void getWhenHasAnyAuthorityRoleUserConfiguredAndAuthorityIsRoleUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserAnyAuthorityConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
				.with(user("user")
				.authorities(new SimpleGrantedAuthority("ROLE_USER")));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenHasAnyAuthorityRoleUserConfiguredAndAuthorityIsRoleAdminThenRespondsWithForbidden()
			throws Exception {
		this.spring.register(RoleUserAnyAuthorityConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithAdmin = get("/")
				.with(user("user")
				.authorities(new SimpleGrantedAuthority("ROLE_ADMIN")));
		// @formatter:on
		this.mvc.perform(requestWithAdmin).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenHasAnyAuthorityRoleUserConfiguredAndNoAuthorityThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(RoleUserAnyAuthorityConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenHasAuthorityRoleUserConfiguredAndAuthorityIsRoleUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserAuthorityConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
				.with(user("user")
				.authorities(new SimpleGrantedAuthority("ROLE_USER")));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenHasAuthorityRoleUserConfiguredAndAuthorityIsRoleAdminThenRespondsWithForbidden()
			throws Exception {
		this.spring.register(RoleUserAuthorityConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithAdmin = get("/")
				.with(user("user")
				.authorities(new SimpleGrantedAuthority("ROLE_ADMIN")));
		// @formatter:on
		this.mvc.perform(requestWithAdmin).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenHasAuthorityRoleUserConfiguredAndNoAuthorityThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(RoleUserAuthorityConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenAuthorityRoleUserOrAdminRequiredAndAuthorityIsRoleUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserOrRoleAdminAuthorityConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
				.with(user("user")
				.authorities(new SimpleGrantedAuthority("ROLE_USER")));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenAuthorityRoleUserOrAdminRequiredAndAuthorityIsRoleAdminThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserOrRoleAdminAuthorityConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithAdmin = get("/")
				.with(user("user")
				.authorities(new SimpleGrantedAuthority("ROLE_ADMIN")));
		// @formatter:on
		this.mvc.perform(requestWithAdmin).andExpect(status().isOk());
	}

	@Test
	public void getWhenAuthorityRoleUserOrAdminRequiredAndAuthorityIsRoleOtherThenRespondsWithForbidden()
			throws Exception {
		this.spring.register(RoleUserOrRoleAdminAuthorityConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithOther = get("/")
				.with(user("user")
				.authorities(new SimpleGrantedAuthority("ROLE_OTHER")));
		// @formatter:on
		this.mvc.perform(requestWithOther).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenAuthorityRoleUserOrAdminAuthRequiredAndNoUserThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(RoleUserOrRoleAdminAuthorityConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenHasRoleUserConfiguredAndRoleIsUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
				.with(user("user")
				.roles("USER"));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenHasRoleUserConfiguredAndRoleIsAdminThenRespondsWithForbidden() throws Exception {
		this.spring.register(RoleUserConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithAdmin = get("/")
				.with(user("user")
				.roles("ADMIN"));
		// @formatter:on
		this.mvc.perform(requestWithAdmin).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenRoleUserOrAdminConfiguredAndRoleIsUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserOrAdminConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
				.with(user("user")
				.roles("USER"));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenRoleUserOrAdminConfiguredAndRoleIsAdminThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserOrAdminConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithAdmin = get("/")
				.with(user("user")
				.roles("ADMIN"));
		// @formatter:on
		this.mvc.perform(requestWithAdmin).andExpect(status().isOk());
	}

	@Test
	public void getWhenRoleUserOrAdminConfiguredAndRoleIsOtherThenRespondsWithForbidden() throws Exception {
		this.spring.register(RoleUserOrAdminConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithRoleOther = get("/")
				.with(user("user")
				.roles("OTHER"));
		// @formatter:on
		this.mvc.perform(requestWithRoleOther).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenDenyAllConfiguredAndNoUserThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(DenyAllConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenDenyAllConfiguredAndUserLoggedInThenRespondsWithForbidden() throws Exception {
		this.spring.register(DenyAllConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
				.with(user("user")
				.roles("USER"));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenPermitAllConfiguredAndNoUserThenRespondsWithOk() throws Exception {
		this.spring.register(PermitAllConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	public void getWhenPermitAllConfiguredAndUserLoggedInThenRespondsWithOk() throws Exception {
		this.spring.register(PermitAllConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
				.with(user("user")
				.roles("USER"));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void authorizeHttpRequestsWhenInvokedTwiceThenUsesOriginalConfiguration() throws Exception {
		this.spring.register(InvokeTwiceDoesNotResetConfig.class, BasicController.class).autowire();
		this.mvc.perform(post("/").with(csrf())).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenServletPathRoleAdminConfiguredAndRoleIsUserThenRespondsWithForbidden() throws Exception {
		this.spring.register(ServletPathConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/spring/")
				.servletPath("/spring")
				.with(user("user")
				.roles("USER"));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenServletPathRoleAdminConfiguredAndRoleIsUserAndWithoutServletPathThenRespondsWithOk()
			throws Exception {
		this.spring.register(ServletPathConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
				.with(user("user")
				.roles("USER"));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenServletPathRoleAdminConfiguredAndRoleIsAdminThenRespondsWithOk() throws Exception {
		this.spring.register(ServletPathConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithAdmin = get("/spring/")
				.servletPath("/spring")
				.with(user("user")
				.roles("ADMIN"));
		// @formatter:on
		this.mvc.perform(requestWithAdmin).andExpect(status().isOk());
	}

	@Test
	public void getWhenAnyRequestAuthenticatedConfiguredAndNoUserThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(AuthenticatedConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenAnyRequestAuthenticatedConfiguredAndUserLoggedInThenRespondsWithOk() throws Exception {
		this.spring.register(AuthenticatedConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
				.with(user("user")
				.roles("USER"));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@EnableWebSecurity
	static class NoRequestsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeHttpRequests(withDefaults())
					.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class NoRequestsConfigWithDefaultConfig {

		@Bean
		SecurityFilterChain filterChainNoRequestsConfigWithDefaultConfig(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeHttpRequests()
					.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class IncompleteMappingConfigWithDefaultConfig {

		@Bean
		SecurityFilterChain filterChainIncompleteMapping(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeHttpRequests()
					.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class IncompleteMappingConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeHttpRequests(AbstractRequestMatcherRegistry::anyRequest)
					.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class AfterAnyRequestConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeHttpRequests((requests) -> requests
						.anyRequest().authenticated()
						.mvcMatchers("/path").hasRole("USER")
					)
					.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class CustomAuthorizationManagerConfig {

		static AuthorizationManager<RequestAuthorizationContext> authorizationManager;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeHttpRequests((requests) -> requests
						.anyRequest().access(authorizationManager)
					)
					.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class ObjectPostProcessorConfig {

		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeHttpRequests((requests) -> requests
						.anyRequest().authenticated()
					)
					.build();
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

	@EnableWebSecurity
	static class RoleUserAnyAuthorityConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.httpBasic()
						.and()
					.authorizeHttpRequests((requests) -> requests
						.anyRequest().hasAnyAuthority("ROLE_USER")
					)
					.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class RoleUserAuthorityConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.httpBasic()
						.and()
					.authorizeHttpRequests((requests) -> requests
						.anyRequest().hasAuthority("ROLE_USER")
					)
					.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class RoleUserOrRoleAdminAuthorityConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.httpBasic()
						.and()
					.authorizeHttpRequests((requests) -> requests
						.anyRequest().hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
					)
					.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class RoleUserConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeHttpRequests((requests) -> requests
						.anyRequest().hasRole("USER")
					)
					.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class RoleUserOrAdminConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeHttpRequests((requests) -> requests
						.anyRequest().hasAnyRole("USER", "ADMIN")
					)
					.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class DenyAllConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.httpBasic()
						.and()
					.authorizeHttpRequests((requests) -> requests
						.anyRequest().denyAll()
					)
					.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class PermitAllConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeHttpRequests((requests) -> requests
						.anyRequest().permitAll()
					)
					.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class InvokeTwiceDoesNotResetConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.httpBasic()
						.and()
					.authorizeHttpRequests((requests) -> requests
						.anyRequest().authenticated()
					)
					.authorizeHttpRequests(withDefaults())
					.build();
			// @formatter:on
		}

	}

	@EnableWebMvc
	@EnableWebSecurity
	static class ServletPathConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.authorizeHttpRequests((requests) -> requests
						.mvcMatchers("/").servletPath("/spring").hasRole("ADMIN")
					)
					.build();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class AuthenticatedConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			return http
					.httpBasic()
						.and()
					.authorizeHttpRequests((requests) -> requests
						.anyRequest().authenticated()
					)
					.build();
			// @formatter:on
		}

	}

	@RestController
	static class BasicController {

		@GetMapping("/")
		void rootGet() {
		}

		@PostMapping("/")
		void rootPost() {
		}

	}

}
