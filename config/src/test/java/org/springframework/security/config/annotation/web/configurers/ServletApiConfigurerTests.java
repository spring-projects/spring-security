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

import java.util.List;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationDetailsSource;
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
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.security.util.FieldUtils;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessEventPublishingLogoutHandler;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.ConfigurableWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link ServletApiConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 * @author Onur Kagan Ozcan
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

	// SEC-2215
	@Test
	public void configureWhenUsingDefaultsThenAuthenticationManagerIsNotNull() {
		this.spring.register(ServletApiConfig.class).autowire();
		assertThat(this.spring.getContext().getBean("customAuthenticationManager")).isNotNull();
	}

	@Test
	public void configureWhenUsingDefaultsThenAuthenticationEntryPointIsLogin() throws Exception {
		this.spring.register(ServletApiConfig.class).autowire();
		this.mvc.perform(formLogin()).andExpect(status().isFound());
	}

	// SEC-2926
	@Test
	public void configureWhenUsingDefaultsThenRolePrefixIsSet() throws Exception {
		this.spring.register(ServletApiConfig.class, AdminController.class).autowire();
		TestingAuthenticationToken user = new TestingAuthenticationToken("user", "pass", "ROLE_ADMIN");
		MockHttpServletRequestBuilder request = get("/admin").with(authentication(user));
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void requestWhenCustomAuthenticationEntryPointThenEntryPointUsed() throws Exception {
		this.spring.register(CustomEntryPointConfig.class).autowire();
		this.mvc.perform(get("/"));
		verify(CustomEntryPointConfig.ENTRYPOINT).commence(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(AuthenticationException.class));
	}

	@Test
	public void servletApiWhenInvokedTwiceThenUsesOriginalRole() throws Exception {
		this.spring.register(DuplicateInvocationsDoesNotOverrideConfig.class, AdminController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = get("/admin")
				.with(user("user").authorities(AuthorityUtils.createAuthorityList("PERMISSION_ADMIN")));
		this.mvc.perform(request)
				.andExpect(status().isOk());
		SecurityMockMvcRequestPostProcessors.UserRequestPostProcessor userWithRoleAdmin = user("user")
				.authorities(AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
		MockHttpServletRequestBuilder requestWithRoleAdmin = get("/admin")
				.with(userWithRoleAdmin);
		this.mvc.perform(requestWithRoleAdmin)
				.andExpect(status().isForbidden());
		// @formatter:on
	}

	@Test
	public void configureWhenSharedObjectTrustResolverThenTrustResolverUsed() throws Exception {
		this.spring.register(SharedTrustResolverConfig.class).autowire();
		this.mvc.perform(get("/"));
		verify(SharedTrustResolverConfig.TR, atLeastOnce()).isAnonymous(any());
	}

	@Test
	public void configureWhenSharedObjectAuthenticationDetailsSourceThenAuthenticationDetailsSourceUsed() throws Exception {
		this.spring.register(SharedAuthenticationDetailsSourceConfig.class).autowire();
		this.mvc.perform(get("/"));
		verify(SharedAuthenticationDetailsSourceConfig.ADS, atLeastOnce()).buildDetails(any());
	}

	@Test
	public void requestWhenServletApiWithDefaultsInLambdaThenUsesDefaultRolePrefix() throws Exception {
		this.spring.register(ServletApiWithDefaultsInLambdaConfig.class, AdminController.class).autowire();
		MockHttpServletRequestBuilder request = get("/admin")
				.with(user("user").authorities(AuthorityUtils.createAuthorityList("ROLE_ADMIN")));
		this.mvc.perform(request).andExpect(status().isOk());
	}

	@Test
	public void requestWhenRolePrefixInLambdaThenUsesCustomRolePrefix() throws Exception {
		this.spring.register(RolePrefixInLambdaConfig.class, AdminController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder requestWithAdminPermission = get("/admin")
				.with(user("user").authorities(AuthorityUtils.createAuthorityList("PERMISSION_ADMIN")));
		this.mvc.perform(requestWithAdminPermission)
				.andExpect(status().isOk());
		MockHttpServletRequestBuilder requestWithAdminRole = get("/admin")
				.with(user("user").authorities(AuthorityUtils.createAuthorityList("ROLE_ADMIN")));
		this.mvc.perform(requestWithAdminRole)
				.andExpect(status().isForbidden());
		// @formatter:on
	}

	@Test
	public void checkSecurityContextAwareAndLogoutFilterHasSameSizeAndHasLogoutSuccessEventPublishingLogoutHandler() {
		this.spring.register(ServletApiWithLogoutConfig.class);
		SecurityContextHolderAwareRequestFilter scaFilter = getFilter(SecurityContextHolderAwareRequestFilter.class);
		LogoutFilter logoutFilter = getFilter(LogoutFilter.class);
		LogoutHandler lfLogoutHandler = getFieldValue(logoutFilter, "handler");
		assertThat(lfLogoutHandler).isInstanceOf(CompositeLogoutHandler.class);
		List<LogoutHandler> scaLogoutHandlers = getFieldValue(scaFilter, "logoutHandlers");
		List<LogoutHandler> lfLogoutHandlers = getFieldValue(lfLogoutHandler, "logoutHandlers");
		assertThat(scaLogoutHandlers).hasSameSizeAs(lfLogoutHandlers);
		assertThat(scaLogoutHandlers).hasAtLeastOneElementOfType(LogoutSuccessEventPublishingLogoutHandler.class);
		assertThat(lfLogoutHandlers).hasAtLeastOneElementOfType(LogoutSuccessEventPublishingLogoutHandler.class);
	}

	@Test
	public void logoutServletApiWhenCsrfDisabled() throws Exception {
		ConfigurableWebApplicationContext context = this.spring.register(CsrfDisabledConfig.class).getContext();
		MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
		MvcResult mvcResult = mockMvc.perform(get("/")).andReturn();
		assertThat(mvcResult.getRequest().getSession(false)).isNull();
	}

	private <T extends Filter> T getFilter(Class<T> filterClass) {
		return (T) getFilters().stream().filter(filterClass::isInstance).findFirst().orElse(null);
	}

	private List<Filter> getFilters() {
		FilterChainProxy proxy = this.spring.getContext().getBean(FilterChainProxy.class);
		return proxy.getFilters("/");
	}

	private <T> T getFieldValue(Object target, String fieldName) {
		try {
			return (T) FieldUtils.getFieldValue(target, fieldName);
		}
		catch (Exception ex) {
			throw new RuntimeException(ex);
		}
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
		AuthenticationManager customAuthenticationManager() throws Exception {
			return super.authenticationManagerBean();
		}

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

	@EnableWebSecurity
	static class SharedTrustResolverConfig extends WebSecurityConfigurerAdapter {

		static AuthenticationTrustResolver TR = spy(AuthenticationTrustResolver.class);

		@Override
		protected void configure(HttpSecurity http) {
			// @formatter:off
			http
				.setSharedObject(AuthenticationTrustResolver.class, TR);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class SharedAuthenticationDetailsSourceConfig extends WebSecurityConfigurerAdapter {

		@SuppressWarnings("unchecked")
		static AuthenticationDetailsSource<HttpServletRequest, ?> ADS = spy(AuthenticationDetailsSource.class);

		@Override
		protected void configure(HttpSecurity http) {
			// @formatter:off
			http
				.setSharedObject(AuthenticationDetailsSource.class, ADS);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class ServletApiWithDefaultsInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.servletApi(withDefaults());
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class RolePrefixInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.servletApi((servletApi) ->
					servletApi
						.rolePrefix("PERMISSION_")
				);
			// @formatter:on
		}

	}

	@RestController
	static class AdminController {

		@GetMapping("/admin")
		void admin(HttpServletRequest request) {
			if (!request.isUserInRole("ADMIN")) {
				throw new AccessDeniedException("This resource is only available to admins");
			}
		}

	}

	@EnableWebSecurity
	static class ServletApiWithLogoutConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.servletApi().and()
				.logout();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CsrfDisabledConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf().disable();
			// @formatter:on
		}

		@RestController
		static class LogoutController {

			@GetMapping("/")
			String logout(HttpServletRequest request) throws ServletException {
				request.getSession().setAttribute("foo", "bar");
				request.logout();
				return "logout";
			}

		}

	}

}
