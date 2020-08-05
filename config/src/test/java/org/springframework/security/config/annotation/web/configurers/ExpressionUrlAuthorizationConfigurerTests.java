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

import java.io.Serializable;
import java.util.Collections;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
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
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
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
 */
public class ExpressionUrlAuthorizationConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenHasRoleStartingWithStringRoleThenException() {
		assertThatThrownBy(() -> this.spring.register(HasRoleStartingWithRoleConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class).hasRootCauseInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining(
						"role should not start with 'ROLE_' since it is automatically inserted. Got 'ROLE_USER'");
	}

	@EnableWebSecurity
	static class HasRoleStartingWithRoleConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("ROLE_USER");
			// @formatter:on
		}

	}

	@Test
	public void configureWhenNoCustomAccessDecisionManagerThenUsesAffirmativeBased() {
		this.spring.register(NoSpecificAccessDecisionManagerConfig.class).autowire();

		verify(NoSpecificAccessDecisionManagerConfig.objectPostProcessor).postProcess(any(AffirmativeBased.class));
	}

	@EnableWebSecurity
	static class NoSpecificAccessDecisionManagerConfig extends WebSecurityConfigurerAdapter {

		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER");
			// @formatter:on
		}

		@Bean
		static ObjectPostProcessor<Object> objectPostProcessor() {
			return objectPostProcessor;
		}

	}

	@Test
	public void configureWhenAuthorizedRequestsAndNoRequestsThenException() {
		assertThatThrownBy(() -> this.spring.register(NoRequestsConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class).hasMessageContaining(
						"At least one mapping is required (i.e. authorizeRequests().anyRequest().authenticated())");
	}

	@EnableWebSecurity
	static class NoRequestsConfig extends WebSecurityConfigurerAdapter {

		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests();
			// @formatter:on
		}

	}

	@Test
	public void configureWhenAnyRequestIncompleteMappingThenException() {
		assertThatThrownBy(() -> this.spring.register(IncompleteMappingConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class).hasMessageContaining("An incomplete mapping was found for ");
	}

	@EnableWebSecurity
	static class IncompleteMappingConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/a").authenticated()
					.anyRequest();
			// @formatter:on
		}

	}

	@Test
	public void getWhenHasAnyAuthorityRoleUserConfiguredAndAuthorityIsRoleUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserAnyAuthorityConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user").authorities(new SimpleGrantedAuthority("ROLE_USER"))))
				.andExpect(status().isOk());
	}

	@Test
	public void getWhenHasAnyAuthorityRoleUserConfiguredAndAuthorityIsRoleAdminThenRespondsWithForbidden()
			throws Exception {
		this.spring.register(RoleUserAnyAuthorityConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user").authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
				.andExpect(status().isForbidden());
	}

	@Test
	public void getWhenHasAnyAuthorityRoleUserConfiguredAndNoAuthorityThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(RoleUserAnyAuthorityConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@EnableWebSecurity
	static class RoleUserAnyAuthorityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().hasAnyAuthority("ROLE_USER");
			// @formatter:on
		}

	}

	@Test
	public void getWhenHasAuthorityRoleUserConfiguredAndAuthorityIsRoleUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserAuthorityConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user").authorities(new SimpleGrantedAuthority("ROLE_USER"))))
				.andExpect(status().isOk());
	}

	@Test
	public void getWhenHasAuthorityRoleUserConfiguredAndAuthorityIsRoleAdminThenRespondsWithForbidden()
			throws Exception {
		this.spring.register(RoleUserAuthorityConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user").authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
				.andExpect(status().isForbidden());
	}

	@Test
	public void getWhenHasAuthorityRoleUserConfiguredAndNoAuthorityThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(RoleUserAuthorityConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@EnableWebSecurity
	static class RoleUserAuthorityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().hasAuthority("ROLE_USER");
			// @formatter:on
		}

	}

	@Test
	public void getWhenAuthorityRoleUserOrAdminRequiredAndAuthorityIsRoleUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserOrRoleAdminAuthorityConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user").authorities(new SimpleGrantedAuthority("ROLE_USER"))))
				.andExpect(status().isOk());
	}

	@Test
	public void getWhenAuthorityRoleUserOrAdminRequiredAndAuthorityIsRoleAdminThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserOrRoleAdminAuthorityConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user").authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
				.andExpect(status().isOk());
	}

	@Test
	public void getWhenAuthorityRoleUserOrAdminRequiredAndAuthorityIsRoleOtherThenRespondsWithForbidden()
			throws Exception {
		this.spring.register(RoleUserOrRoleAdminAuthorityConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user").authorities(new SimpleGrantedAuthority("ROLE_OTHER"))))
				.andExpect(status().isForbidden());
	}

	@Test
	public void getWhenAuthorityRoleUserOrAdminAuthRequiredAndNoUserThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(RoleUserOrRoleAdminAuthorityConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@EnableWebSecurity
	static class RoleUserOrRoleAdminAuthorityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().hasAnyAuthority("ROLE_USER", "ROLE_ADMIN");
			// @formatter:on
		}

	}

	@Test
	public void getWhenHasAnyRoleUserConfiguredAndRoleIsUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user").roles("USER"))).andExpect(status().isOk());
	}

	@Test
	public void getWhenHasAnyRoleUserConfiguredAndRoleIsAdminThenRespondsWithForbidden() throws Exception {
		this.spring.register(RoleUserConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user").roles("ADMIN"))).andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class RoleUserConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasAnyRole("USER");
			// @formatter:on
		}

	}

	@Test
	public void getWhenRoleUserOrAdminConfiguredAndRoleIsUserThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserOrAdminConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user").roles("USER"))).andExpect(status().isOk());
	}

	@Test
	public void getWhenRoleUserOrAdminConfiguredAndRoleIsAdminThenRespondsWithOk() throws Exception {
		this.spring.register(RoleUserOrAdminConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user").roles("ADMIN"))).andExpect(status().isOk());
	}

	@Test
	public void getWhenRoleUserOrAdminConfiguredAndRoleIsOtherThenRespondsWithForbidden() throws Exception {
		this.spring.register(RoleUserOrAdminConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user").roles("OTHER"))).andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class RoleUserOrAdminConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasAnyRole("USER", "ADMIN");
			// @formatter:on
		}

	}

	@Test
	public void getWhenHasIpAddressConfiguredAndIpAddressMatchesThenRespondsWithOk() throws Exception {
		this.spring.register(HasIpAddressConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(request -> {
			request.setRemoteAddr("192.168.1.0");
			return request;
		})).andExpect(status().isOk());
	}

	@Test
	public void getWhenHasIpAddressConfiguredAndIpAddressDoesNotMatchThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(HasIpAddressConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(request -> {
			request.setRemoteAddr("192.168.1.1");
			return request;
		})).andExpect(status().isUnauthorized());
	}

	@EnableWebSecurity
	static class HasIpAddressConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().hasIpAddress("192.168.1.0");
			// @formatter:on
		}

	}

	@Test
	public void getWhenAnonymousConfiguredAndAnonymousUserThenRespondsWithOk() throws Exception {
		this.spring.register(AnonymousConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	public void getWhenAnonymousConfiguredAndLoggedInUserThenRespondsWithForbidden() throws Exception {
		this.spring.register(AnonymousConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user"))).andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class AnonymousConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().anonymous();
			// @formatter:on
		}

	}

	@Test
	public void getWhenRememberMeConfiguredAndNoUserThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(RememberMeConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenRememberMeConfiguredAndRememberMeTokenThenRespondsWithOk() throws Exception {
		this.spring.register(RememberMeConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(authentication(
				new RememberMeAuthenticationToken("key", "user", AuthorityUtils.createAuthorityList("ROLE_USER")))))
				.andExpect(status().isOk());
	}

	@EnableWebSecurity
	static class RememberMeConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.rememberMe()
					.and()
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().rememberMe();
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
	public void getWhenDenyAllConfiguredAndNoUserThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(DenyAllConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWheDenyAllConfiguredAndUserLoggedInThenRespondsWithForbidden() throws Exception {
		this.spring.register(DenyAllConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user").roles("USER"))).andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class DenyAllConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().denyAll();
			// @formatter:on
		}

	}

	@Test
	public void getWhenNotDenyAllConfiguredAndNoUserThenRespondsWithOk() throws Exception {
		this.spring.register(NotDenyAllConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	public void getWhenNotDenyAllConfiguredAndRememberMeTokenThenRespondsWithOk() throws Exception {
		this.spring.register(NotDenyAllConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(authentication(
				new RememberMeAuthenticationToken("key", "user", AuthorityUtils.createAuthorityList("ROLE_USER")))))
				.andExpect(status().isOk());
	}

	@EnableWebSecurity
	static class NotDenyAllConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().not().denyAll();
			// @formatter:on
		}

	}

	@Test
	public void getWhenFullyAuthenticatedConfiguredAndRememberMeTokenThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(FullyAuthenticatedConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(authentication(
				new RememberMeAuthenticationToken("key", "user", AuthorityUtils.createAuthorityList("ROLE_USER")))))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenFullyAuthenticatedConfiguredAndUserThenRespondsWithOk() throws Exception {
		this.spring.register(FullyAuthenticatedConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/").with(user("user").roles("USER"))).andExpect(status().isOk());
	}

	@EnableWebSecurity
	static class FullyAuthenticatedConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.rememberMe()
					.and()
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().fullyAuthenticated();
			// @formatter:on
		}

	}

	@Test
	public void getWhenAccessRoleUserOrGetRequestConfiguredThenRespondsWithOk() throws Exception {
		this.spring.register(AccessConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	public void postWhenAccessRoleUserOrGetRequestConfiguredAndRoleUserThenRespondsWithOk() throws Exception {
		this.spring.register(AccessConfig.class, BasicController.class).autowire();

		this.mvc.perform(post("/").with(csrf()).with(user("user").roles("USER"))).andExpect(status().isOk());
	}

	@Test
	public void postWhenAccessRoleUserOrGetRequestConfiguredThenRespondsWithUnauthorized() throws Exception {
		this.spring.register(AccessConfig.class, BasicController.class).autowire();

		this.mvc.perform(post("/").with(csrf())).andExpect(status().isUnauthorized());
	}

	@EnableWebSecurity
	static class AccessConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.rememberMe()
					.and()
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().access("hasRole('ROLE_USER') or request.method == 'GET'");
			// @formatter:on
		}

	}

	@Test
	public void authorizeRequestsWhenInvokedTwiceThenUsesOriginalConfiguration() throws Exception {
		this.spring.register(InvokeTwiceDoesNotResetConfig.class, BasicController.class).autowire();

		this.mvc.perform(post("/").with(csrf())).andExpect(status().isUnauthorized());
	}

	@EnableWebSecurity
	static class InvokeTwiceDoesNotResetConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.authorizeRequests();
			// @formatter:on
		}

	}

	@Test
	public void configureWhenUsingAllAuthorizeRequestPropertiesThenCompiles() {
		this.spring.register(AllPropertiesWorkConfig.class).autowire();
	}

	@EnableWebSecurity
	static class AllPropertiesWorkConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			SecurityExpressionHandler<FilterInvocation> handler = new DefaultWebSecurityExpressionHandler();
			WebExpressionVoter expressionVoter = new WebExpressionVoter();
			AffirmativeBased adm = new AffirmativeBased(Collections.singletonList(expressionVoter));
			// @formatter:off
			http
				.authorizeRequests()
					.expressionHandler(handler)
					.accessDecisionManager(adm)
					.filterSecurityInterceptorOncePerRequest(true)
					.antMatchers("/a", "/b").hasRole("ADMIN")
					.anyRequest().permitAll()
					.and()
				.formLogin();
			// @formatter:on
		}

	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenApplicationListenerInvokedOnAuthorizedEvent()
			throws Exception {
		this.spring.register(AuthorizedRequestsWithPostProcessorConfig.class).autowire();

		this.mvc.perform(get("/"));

		verify(AuthorizedRequestsWithPostProcessorConfig.AL).onApplicationEvent(any(AuthorizedEvent.class));
	}

	@EnableWebSecurity
	static class AuthorizedRequestsWithPostProcessorConfig extends WebSecurityConfigurerAdapter {

		static ApplicationListener<AuthorizedEvent> AL = mock(ApplicationListener.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().permitAll()
					.withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
						public <O extends FilterSecurityInterceptor> O postProcess(
								O fsi) {
							fsi.setPublishAuthorizationSuccess(true);
							return fsi;
						}
					});
			// @formatter:on
		}

		@Bean
		public ApplicationListener<AuthorizedEvent> applicationListener() {
			return AL;
		}

	}

	@Test
	public void getWhenPermissionCheckAndRoleDoesNotMatchThenRespondsWithForbidden() throws Exception {
		this.spring.register(UseBeansInExpressions.class, WildcardController.class).autowire();

		this.mvc.perform(get("/admin").with(user("user").roles("USER"))).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenPermissionCheckAndRoleMatchesThenRespondsWithOk() throws Exception {
		this.spring.register(UseBeansInExpressions.class, WildcardController.class).autowire();

		this.mvc.perform(get("/user").with(user("user").roles("USER"))).andExpect(status().isOk());
	}

	@Test
	public void getWhenPermissionCheckAndAuthenticationNameMatchesThenRespondsWithOk() throws Exception {
		this.spring.register(UseBeansInExpressions.class, WildcardController.class).autowire();

		this.mvc.perform(get("/allow").with(user("user").roles("USER"))).andExpect(status().isOk());
	}

	@Test
	public void getWhenPermissionCheckAndAuthenticationNameDoesNotMatchThenRespondsWithForbidden() throws Exception {
		this.spring.register(UseBeansInExpressions.class, WildcardController.class).autowire();

		this.mvc.perform(get("/deny").with(user("user").roles("USER"))).andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class UseBeansInExpressions extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/admin").hasRole("ADMIN")
					.antMatchers("/user").hasRole("USER")
					.antMatchers("/allow").access("@permission.check(authentication,'user')")
					.anyRequest().access("@permission.check(authentication,'admin')");
			// @formatter:on
		}

		@Bean
		public Checker permission() {
			return new Checker();
		}

		static class Checker {

			public boolean check(Authentication authentication, String customArg) {
				return authentication.getName().contains(customArg);
			}

		}

	}

	@Test
	public void getWhenCustomExpressionHandlerAndRoleDoesNotMatchThenRespondsWithForbidden() throws Exception {
		this.spring.register(CustomExpressionRootConfig.class, WildcardController.class).autowire();

		this.mvc.perform(get("/admin").with(user("user").roles("USER"))).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenCustomExpressionHandlerAndRoleMatchesThenRespondsWithOk() throws Exception {
		this.spring.register(CustomExpressionRootConfig.class, WildcardController.class).autowire();

		this.mvc.perform(get("/user").with(user("user").roles("USER"))).andExpect(status().isOk());
	}

	@Test
	public void getWhenCustomExpressionHandlerAndAuthenticationNameMatchesThenRespondsWithOk() throws Exception {
		this.spring.register(CustomExpressionRootConfig.class, WildcardController.class).autowire();

		this.mvc.perform(get("/allow").with(user("user").roles("USER"))).andExpect(status().isOk());
	}

	@Test
	public void getWhenCustomExpressionHandlerAndAuthenticationNameDoesNotMatchThenRespondsWithForbidden()
			throws Exception {
		this.spring.register(CustomExpressionRootConfig.class, WildcardController.class).autowire();

		this.mvc.perform(get("/deny").with(user("user").roles("USER"))).andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class CustomExpressionRootConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.expressionHandler(expressionHandler())
					.antMatchers("/admin").hasRole("ADMIN")
					.antMatchers("/user").hasRole("USER")
					.antMatchers("/allow").access("check('user')")
					.anyRequest().access("check('admin')");
			// @formatter:on
		}

		@Bean
		public CustomExpressionHandler expressionHandler() {
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

	// SEC-3011
	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnAccessDecisionManager() {
		this.spring.register(Sec3011Config.class).autowire();

		verify(Sec3011Config.objectPostProcessor).postProcess(any(AccessDecisionManager.class));
	}

	@EnableWebSecurity
	static class Sec3011Config extends WebSecurityConfigurerAdapter {

		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
				http
				.authorizeRequests()
					.anyRequest().authenticated();
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
		static ObjectPostProcessor<Object> objectPostProcessor() {
			return objectPostProcessor;
		}

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

	@EnableWebSecurity
	static class PermissionEvaluatorConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/allow").access("hasPermission('ID', 'TYPE', 'PERMISSION')")
					.antMatchers("/allowObject").access("hasPermission('TESTOBJ', 'PERMISSION')")
					.antMatchers("/deny").access("hasPermission('ID', 'TYPE', 'NO PERMISSION')")
					.antMatchers("/denyObject").access("hasPermission('TESTOBJ', 'NO PERMISSION')")
					.anyRequest().permitAll();
			// @formatter:on
		}

		@Bean
		public PermissionEvaluator permissionEvaluator() {
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

	@Test
	public void getWhenRegisteringRoleHierarchyAndRelatedRoleAllowedThenRespondsWithOk() throws Exception {
		this.spring.register(RoleHierarchyConfig.class, WildcardController.class).autowire();

		this.mvc.perform(get("/allow").with(user("user").roles("USER"))).andExpect(status().isOk());
	}

	@Test
	public void getWhenRegisteringRoleHierarchyAndNoRelatedRolesAllowedThenRespondsWithForbidden() throws Exception {
		this.spring.register(RoleHierarchyConfig.class, WildcardController.class).autowire();

		this.mvc.perform(get("/deny").with(user("user").roles("USER"))).andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class RoleHierarchyConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.antMatchers("/allow").access("hasRole('MEMBER')")
					.antMatchers("/deny").access("hasRole('ADMIN')")
					.anyRequest().permitAll();
			// @formatter:on
		}

		@Bean
		public RoleHierarchy roleHierarchy() {
			RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
			roleHierarchy.setHierarchy("ROLE_USER > ROLE_MEMBER");
			return roleHierarchy;
		}

	}

	@RestController
	static class BasicController {

		@GetMapping("/")
		public void rootGet() {
		}

		@PostMapping("/")
		public void rootPost() {
		}

	}

	@RestController
	static class WildcardController {

		@GetMapping("/{path}")
		public void wildcard(@PathVariable String path) {
		}

	}

	static class ReflectingObjectPostProcessor implements ObjectPostProcessor<Object> {

		@Override
		public <O> O postProcess(O object) {
			return object;
		}

	}

}
