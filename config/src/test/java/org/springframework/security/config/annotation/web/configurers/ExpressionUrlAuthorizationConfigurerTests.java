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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.event.AuthorizedEvent;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link ExpressionUrlAuthorizationConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 * @author Yanming Zhou
 */
@ExtendWith(SpringTestContextExtension.class)
public class ExpressionUrlAuthorizationConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenHasRoleStartingWithStringRoleThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(HasRoleStartingWithRoleConfig.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class).withMessageContaining(
						"role should not start with 'ROLE_' since it is automatically inserted. Got 'ROLE_USER'");
	}

	@Test
	public void configureWhenNoCustomAccessDecisionManagerThenUsesAffirmativeBased() {
		this.spring.register(NoSpecificAccessDecisionManagerConfig.class).autowire();
		verify(NoSpecificAccessDecisionManagerConfig.objectPostProcessor).postProcess(any(AffirmativeBased.class));
	}

	@Test
	public void configureWhenAuthorizedRequestsAndNoRequestsThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(NoRequestsConfig.class).autowire()).withMessageContaining(
						"At least one mapping is required (i.e. authorizeRequests().anyRequest().authenticated())");
	}

	@Test
	public void configureWhenAnyRequestIncompleteMappingThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(IncompleteMappingConfig.class).autowire())
				.withMessageContaining("An incomplete mapping was found for ");
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
		MockHttpServletRequestBuilder requestWithUser = get("/")
				.with(user("user")
				.authorities(new SimpleGrantedAuthority("ROLE_ADMIN")));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenAuthorityRoleUserOrAdminRequiredAndAuthorityIsRoleOtherThenRespondsWithForbidden()
			throws Exception {
		this.spring.register(RoleUserOrRoleAdminAuthorityConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
				.with(user("user")
				.authorities(new SimpleGrantedAuthority("ROLE_OTHER")));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenAuthorityRoleUserOrAdminAuthRequiredAndNoUserThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(RoleUserOrRoleAdminAuthorityConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenHasAnyRoleUserConfiguredAndRoleIsUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
				.with(user("user")
				.roles("USER"));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenHasAnyRoleUserConfiguredAndRoleIsAdminThenRespondsWithForbidden() throws Exception {
		this.spring.register(RoleUserConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithAdmin = get("/")
				.with(user("user")
				.roles("ADMIN"));
		// @formatter:on
		this.mvc.perform(requestWithAdmin).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenHasAnyRoleUserWithTestRolePrefixConfiguredAndRoleIsUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserWithTestRolePrefixConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
				.with(user("user")
				.authorities(new SimpleGrantedAuthority("TEST_USER")));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenHasAnyRoleUserWithEmptyRolePrefixConfiguredAndRoleIsUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserWithEmptyRolePrefixConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
				.with(user("user")
				.authorities(new SimpleGrantedAuthority("USER")));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
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
		// <editor-fold desc="Description">
		MockHttpServletRequestBuilder requestWithRoleOther = get("/").with(user("user").roles("OTHER"));
		// </editor-fold>
		this.mvc.perform(requestWithRoleOther).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenRoleUserOrAdminWithTestRolePrefixConfiguredAndRoleIsUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserOrAdminWithTestRolePrefixConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
			.with(user("user")
			.authorities(new SimpleGrantedAuthority("TEST_USER")));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenRoleUserOrAdminWithEmptyRolePrefixConfiguredAndRoleIsUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserOrAdminWithEmptyRolePrefixConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = get("/")
			.with(user("user")
			.authorities(new SimpleGrantedAuthority("USER")));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenHasIpAddressConfiguredAndIpAddressMatchesThenRespondsWithOk() throws Exception {
		this.spring.register(HasIpAddressConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/").with((request) -> {
			request.setRemoteAddr("192.168.1.0");
			return request;
		})).andExpect(status().isOk());
	}

	@Test
	public void getWhenHasIpAddressConfiguredAndIpAddressDoesNotMatchThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(HasIpAddressConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/").with((request) -> {
			request.setRemoteAddr("192.168.1.1");
			return request;
		})).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenAnonymousConfiguredAndAnonymousUserThenRespondsWithOk() throws Exception {
		this.spring.register(AnonymousConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	public void getWhenAnonymousConfiguredAndLoggedInUserThenRespondsWithForbidden() throws Exception {
		this.spring.register(AnonymousConfig.class, BasicController.class).autowire();
		MockHttpServletRequestBuilder requestWithUser = get("/").with(user("user"));
		this.mvc.perform(requestWithUser).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenRememberMeConfiguredAndNoUserThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(RememberMeConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenRememberMeConfiguredAndRememberMeTokenThenRespondsWithOk() throws Exception {
		this.spring.register(RememberMeConfig.class, BasicController.class).autowire();
		RememberMeAuthenticationToken rememberme = new RememberMeAuthenticationToken("key", "user",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		MockHttpServletRequestBuilder requestWithRememberme = get("/").with(authentication(rememberme));
		this.mvc.perform(requestWithRememberme).andExpect(status().isOk());
	}

	@Test
	public void getWhenDenyAllConfiguredAndNoUserThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(DenyAllConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWheDenyAllConfiguredAndUserLoggedInThenRespondsWithForbidden() throws Exception {
		this.spring.register(DenyAllConfig.class, BasicController.class).autowire();
		MockHttpServletRequestBuilder requestWithUser = get("/").with(user("user").roles("USER"));
		this.mvc.perform(requestWithUser).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenNotDenyAllConfiguredAndNoUserThenRespondsWithOk() throws Exception {
		this.spring.register(NotDenyAllConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	public void getWhenNotDenyAllConfiguredAndRememberMeTokenThenRespondsWithOk() throws Exception {
		this.spring.register(NotDenyAllConfig.class, BasicController.class).autowire();
		RememberMeAuthenticationToken rememberme = new RememberMeAuthenticationToken("key", "user",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		MockHttpServletRequestBuilder requestWithRememberme = get("/").with(authentication(rememberme));
		this.mvc.perform(requestWithRememberme).andExpect(status().isOk());
	}

	@Test
	public void getWhenFullyAuthenticatedConfiguredAndRememberMeTokenThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(FullyAuthenticatedConfig.class, BasicController.class).autowire();
		RememberMeAuthenticationToken rememberme = new RememberMeAuthenticationToken("key", "user",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		MockHttpServletRequestBuilder requestWithRememberme = get("/").with(authentication(rememberme));
		this.mvc.perform(requestWithRememberme).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenFullyAuthenticatedConfiguredAndUserThenRespondsWithOk() throws Exception {
		this.spring.register(FullyAuthenticatedConfig.class, BasicController.class).autowire();
		MockHttpServletRequestBuilder requestWithUser = get("/").with(user("user").roles("USER"));
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenAccessRoleUserOrGetRequestConfiguredThenRespondsWithOk() throws Exception {
		this.spring.register(AccessConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	public void postWhenAccessRoleUserOrGetRequestConfiguredAndRoleUserThenRespondsWithOk() throws Exception {
		this.spring.register(AccessConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithUser = post("/")
				.with(csrf())
				.with(user("user").roles("USER"));
		// @formatter:on
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void postWhenAccessRoleUserOrGetRequestConfiguredThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(AccessConfig.class, BasicController.class).autowire();
		MockHttpServletRequestBuilder requestWithCsrf = post("/").with(csrf());
		this.mvc.perform(requestWithCsrf).andExpect(status().isUnauthorized());
	}

	@Test
	public void authorizeRequestsWhenInvokedTwiceThenUsesOriginalConfiguration() throws Exception {
		this.spring.register(InvokeTwiceDoesNotResetConfig.class, BasicController.class).autowire();
		MockHttpServletRequestBuilder requestWithCsrf = post("/").with(csrf());
		this.mvc.perform(requestWithCsrf).andExpect(status().isUnauthorized());
	}

	@Test
	public void configureWhenUsingAllAuthorizeRequestPropertiesThenCompiles() {
		this.spring.register(AllPropertiesWorkConfig.class).autowire();
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenApplicationListenerInvokedOnAuthorizedEvent()
			throws Exception {
		AuthorizedEventApplicationListener.clearEvents();
		this.spring.register(AuthorizedRequestsWithPostProcessorConfig.class).autowire();
		this.mvc.perform(get("/"));
		assertThat(AuthorizedEventApplicationListener.EVENTS).isNotEmpty();
	}

	@Test
	public void getWhenPermissionCheckAndRoleDoesNotMatchThenRespondsWithForbidden() throws Exception {
		this.spring.register(UseBeansInExpressions.class, WildcardController.class).autowire();
		MockHttpServletRequestBuilder requestWithUser = get("/admin").with(user("user").roles("USER"));
		this.mvc.perform(requestWithUser).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenPermissionCheckAndRoleMatchesThenRespondsWithOk() throws Exception {
		this.spring.register(UseBeansInExpressions.class, WildcardController.class).autowire();
		MockHttpServletRequestBuilder requestWithUser = get("/user").with(user("user").roles("USER"));
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenPermissionCheckAndAuthenticationNameMatchesThenRespondsWithOk() throws Exception {
		this.spring.register(UseBeansInExpressions.class, WildcardController.class).autowire();
		MockHttpServletRequestBuilder requestWithUser = get("/allow").with(user("user").roles("USER"));
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenPermissionCheckAndAuthenticationNameDoesNotMatchThenRespondsWithForbidden() throws Exception {
		this.spring.register(UseBeansInExpressions.class, WildcardController.class).autowire();
		MockHttpServletRequestBuilder requestWithUser = get("/deny").with(user("user").roles("USER"));
		this.mvc.perform(requestWithUser).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenCustomExpressionHandlerAndRoleDoesNotMatchThenRespondsWithForbidden() throws Exception {
		this.spring.register(CustomExpressionRootConfig.class, WildcardController.class).autowire();
		MockHttpServletRequestBuilder requestWithUser = get("/admin").with(user("user").roles("USER"));
		this.mvc.perform(requestWithUser).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenCustomExpressionHandlerAndRoleMatchesThenRespondsWithOk() throws Exception {
		this.spring.register(CustomExpressionRootConfig.class, WildcardController.class).autowire();
		MockHttpServletRequestBuilder requestWithUser = get("/user").with(user("user").roles("USER"));
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenCustomExpressionHandlerAndAuthenticationNameMatchesThenRespondsWithOk() throws Exception {
		this.spring.register(CustomExpressionRootConfig.class, WildcardController.class).autowire();
		MockHttpServletRequestBuilder requestWithUser = get("/allow").with(user("user").roles("USER"));
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenCustomExpressionHandlerAndAuthenticationNameDoesNotMatchThenRespondsWithForbidden()
			throws Exception {
		this.spring.register(CustomExpressionRootConfig.class, WildcardController.class).autowire();
		MockHttpServletRequestBuilder requestWithUser = get("/deny").with(user("user").roles("USER"));
		this.mvc.perform(requestWithUser).andExpect(status().isForbidden());
	}

	// SEC-3011
	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnAccessDecisionManager() {
		this.spring.register(Sec3011Config.class).autowire();
		verify(Sec3011Config.objectPostProcessor).postProcess(any(AccessDecisionManager.class));
	}

	@Test
	public void getWhenRegisteringPermissionEvaluatorAndPermissionWithIdAndTypeMatchesThenRespondsWithOk()
			throws Exception {
		this.spring.register(PermissionEvaluatorConfig.class, WildcardController.class).autowire();
		this.mvc.perform(get("/allow")).andExpect(status().isOk());
	}

	@Test
	public void getWhenRegisteringPermissionEvaluatorAndPermissionWithIdAndTypeDoesNotMatchThenRespondsWithForbidden()
			throws Exception {
		this.spring.register(PermissionEvaluatorConfig.class, WildcardController.class).autowire();
		this.mvc.perform(get("/deny")).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenRegisteringPermissionEvaluatorAndPermissionWithObjectMatchesThenRespondsWithOk()
			throws Exception {
		this.spring.register(PermissionEvaluatorConfig.class, WildcardController.class).autowire();
		this.mvc.perform(get("/allowObject")).andExpect(status().isOk());
	}

	@Test
	public void getWhenRegisteringPermissionEvaluatorAndPermissionWithObjectDoesNotMatchThenRespondsWithForbidden()
			throws Exception {
		this.spring.register(PermissionEvaluatorConfig.class, WildcardController.class).autowire();
		this.mvc.perform(get("/denyObject")).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenRegisteringRoleHierarchyAndRelatedRoleAllowedThenRespondsWithOk() throws Exception {
		this.spring.register(RoleHierarchyConfig.class, WildcardController.class).autowire();
		MockHttpServletRequestBuilder requestWithUser = get("/allow").with(user("user").roles("USER"));
		this.mvc.perform(requestWithUser).andExpect(status().isOk());
	}

	@Test
	public void getWhenRegisteringRoleHierarchyAndNoRelatedRolesAllowedThenRespondsWithForbidden() throws Exception {
		this.spring.register(RoleHierarchyConfig.class, WildcardController.class).autowire();
		MockHttpServletRequestBuilder requestWithUser = get("/deny").with(user("user").roles("USER"));
		this.mvc.perform(requestWithUser).andExpect(status().isForbidden());
	}

	@Configuration
	@EnableWebSecurity
	static class HasRoleStartingWithRoleConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("ROLE_USER");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NoSpecificAccessDecisionManagerConfig {

		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER");
			return http.build();
			// @formatter:on
		}

		@Bean
		static ObjectPostProcessor<Object> objectPostProcessor() {
			return objectPostProcessor;
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NoRequestsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class IncompleteMappingConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.requestMatchers("/a").authenticated()
					.anyRequest();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RoleUserAnyAuthorityConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().hasAnyAuthority("ROLE_USER");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RoleUserAuthorityConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().hasAuthority("ROLE_USER");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RoleUserOrRoleAdminAuthorityConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().hasAnyAuthority("ROLE_USER", "ROLE_ADMIN");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RoleUserConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasAnyRole("USER");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RoleUserWithTestRolePrefixConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasAnyRole("USER");
			return http.build();
			// @formatter:on
		}

		@Bean
		GrantedAuthorityDefaults grantedAuthorityDefaults() {
			return new GrantedAuthorityDefaults("TEST_");
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RoleUserWithEmptyRolePrefixConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasAnyRole("USER");
			return http.build();
			// @formatter:on
		}

		@Bean
		GrantedAuthorityDefaults grantedAuthorityDefaults() {
			return new GrantedAuthorityDefaults("");
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RoleUserOrAdminConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasAnyRole("USER", "ADMIN");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RoleUserOrAdminWithTestRolePrefixConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasAnyRole("USER", "ADMIN");
			return http.build();
			// @formatter:on
		}

		@Bean
		GrantedAuthorityDefaults grantedAuthorityDefaults() {
			return new GrantedAuthorityDefaults("TEST_");
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RoleUserOrAdminWithEmptyRolePrefixConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasAnyRole("USER", "ADMIN");
			return http.build();
			// @formatter:on
		}

		@Bean
		GrantedAuthorityDefaults grantedAuthorityDefaults() {
			return new GrantedAuthorityDefaults("");
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HasIpAddressConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().hasIpAddress("192.168.1.0");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AnonymousConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().anonymous();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RememberMeConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.rememberMe()
					.and()
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().rememberMe();
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DenyAllConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().denyAll();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NotDenyAllConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().not().denyAll();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class FullyAuthenticatedConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.rememberMe()
					.and()
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().fullyAuthenticated();
			return http.build();
			// @formatter:on
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AccessConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.rememberMe()
					.and()
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().access("hasRole('ROLE_USER') or request.method == 'GET'");
			return http.build();
			// @formatter:on
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class InvokeTwiceDoesNotResetConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.authorizeRequests();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class AllPropertiesWorkConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			SecurityExpressionHandler<FilterInvocation> handler = new DefaultWebSecurityExpressionHandler();
			WebExpressionVoter expressionVoter = new WebExpressionVoter();
			AffirmativeBased adm = new AffirmativeBased(Collections.singletonList(expressionVoter));
			// @formatter:off
			http
				.authorizeRequests()
					.expressionHandler(handler)
					.accessDecisionManager(adm)
					.filterSecurityInterceptorOncePerRequest(true)
					.requestMatchers("/a", "/b").hasRole("ADMIN")
					.anyRequest().permitAll()
					.and()
				.formLogin();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AuthorizedRequestsWithPostProcessorConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().permitAll()
					.withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
						@Override
						public <O extends FilterSecurityInterceptor> O postProcess(
								O fsi) {
							fsi.setPublishAuthorizationSuccess(true);
							return fsi;
						}
					});
			return http.build();
			// @formatter:on
		}

		@Bean
		ApplicationListener<AuthorizedEvent> applicationListener() {
			return new AuthorizedEventApplicationListener();
		}

	}

	static class AuthorizedEventApplicationListener implements ApplicationListener<AuthorizedEvent> {

		static final List<AuthorizedEvent> EVENTS = new ArrayList<>();

		@Override
		public void onApplicationEvent(AuthorizedEvent event) {
			EVENTS.add(event);
		}

		static void clearEvents() {
			EVENTS.clear();
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class UseBeansInExpressions {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.requestMatchers("/admin").hasRole("ADMIN")
					.requestMatchers("/user").hasRole("USER")
					.requestMatchers("/allow").access("@permission.check(authentication,'user')")
					.anyRequest().access("@permission.check(authentication,'admin')");
			return http.build();
			// @formatter:on
		}

		@Bean
		Checker permission() {
			return new Checker();
		}

		static class Checker {

			public boolean check(Authentication authentication, String customArg) {
				return authentication.getName().contains(customArg);
			}

		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class CustomExpressionRootConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.expressionHandler(expressionHandler())
					.requestMatchers("/admin").hasRole("ADMIN")
					.requestMatchers("/user").hasRole("USER")
					.requestMatchers("/allow").access("check('user')")
					.anyRequest().access("check('admin')");
			return http.build();
			// @formatter:on
		}

		@Bean
		CustomExpressionHandler expressionHandler() {
			return new CustomExpressionHandler();
		}

		static class CustomExpressionHandler extends DefaultWebSecurityExpressionHandler {

			@Override
			protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication,
					FilterInvocation fi) {
				WebSecurityExpressionRoot root = new CustomExpressionRoot(authentication, fi);
				root.setPermissionEvaluator(getPermissionEvaluator());
				root.setTrustResolver(new AuthenticationTrustResolverImpl());
				root.setRoleHierarchy(getRoleHierarchy());
				return root;
			}

		}

		static class CustomExpressionRoot extends WebSecurityExpressionRoot {

			CustomExpressionRoot(Authentication a, FilterInvocation fi) {
				super(a, fi);
			}

			public boolean check(String customArg) {
				Authentication auth = this.getAuthentication();
				return auth.getName().contains(customArg);
			}

		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSecurity
	static class Sec3011Config {

		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
				http
				.authorizeRequests()
					.anyRequest().authenticated();
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

		@Bean
		static ObjectPostProcessor<Object> objectPostProcessor() {
			return objectPostProcessor;
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class PermissionEvaluatorConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.requestMatchers("/allow").access("hasPermission('ID', 'TYPE', 'PERMISSION')")
					.requestMatchers("/allowObject").access("hasPermission('TESTOBJ', 'PERMISSION')")
					.requestMatchers("/deny").access("hasPermission('ID', 'TYPE', 'NO PERMISSION')")
					.requestMatchers("/denyObject").access("hasPermission('TESTOBJ', 'NO PERMISSION')")
					.anyRequest().permitAll();
			return http.build();
			// @formatter:on
		}

		@Bean
		PermissionEvaluator permissionEvaluator() {
			return new PermissionEvaluator() {
				@Override
				public boolean hasPermission(Authentication authentication, Object targetDomainObject,
						Object permission) {
					return "TESTOBJ".equals(targetDomainObject) && "PERMISSION".equals(permission);
				}

				@Override
				public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
						Object permission) {
					return "ID".equals(targetId) && "TYPE".equals(targetType) && "PERMISSION".equals(permission);
				}
			};
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class RoleHierarchyConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.requestMatchers("/allow").access("hasRole('MEMBER')")
					.requestMatchers("/deny").access("hasRole('ADMIN')")
					.anyRequest().permitAll();
			return http.build();
			// @formatter:on
		}

		@Bean
		RoleHierarchy roleHierarchy() {
			RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
			roleHierarchy.setHierarchy("ROLE_USER > ROLE_MEMBER");
			return roleHierarchy;
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

	@RestController
	static class WildcardController {

		@GetMapping("/{path}")
		void wildcard(@PathVariable String path) {
		}

	}

	static class ReflectingObjectPostProcessor implements ObjectPostProcessor<Object> {

		@Override
		public <O> O postProcess(O object) {
			return object;
		}

	}

}
