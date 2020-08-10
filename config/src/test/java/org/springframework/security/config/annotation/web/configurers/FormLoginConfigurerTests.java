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
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.config.users.AuthenticationTestConfiguration;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.logout;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @author Eleftheria Stein
 * @since 5.1
 */
public class FormLoginConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void requestCache() throws Exception {
		this.spring.register(RequestCacheConfig.class, AuthenticationTestConfiguration.class).autowire();

		RequestCacheConfig config = this.spring.getContext().getBean(RequestCacheConfig.class);

		this.mockMvc.perform(formLogin()).andExpect(authenticated());

		verify(config.requestCache).getRequest(any(), any());
	}

	@EnableWebSecurity
	static class RequestCacheConfig extends WebSecurityConfigurerAdapter {

		private RequestCache requestCache = mock(RequestCache.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin().and()
				.requestCache()
					.requestCache(this.requestCache);
			// @formatter:on
		}

	}

	@Test
	public void requestCacheAsBean() throws Exception {
		this.spring.register(RequestCacheBeanConfig.class, AuthenticationTestConfiguration.class).autowire();

		RequestCache requestCache = this.spring.getContext().getBean(RequestCache.class);

		this.mockMvc.perform(formLogin()).andExpect(authenticated());

		verify(requestCache).getRequest(any(), any());
	}

	@EnableWebSecurity
	static class RequestCacheBeanConfig {

		@Bean
		RequestCache requestCache() {
			return mock(RequestCache.class);
		}

	}

	@Test
	public void loginWhenFormLoginConfiguredThenHasDefaultUsernameAndPasswordParameterNames() throws Exception {
		this.spring.register(FormLoginConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("username", "user").password("password", "password"))
				.andExpect(status().isFound()).andExpect(redirectedUrl("/"));
	}

	@Test
	public void loginWhenFormLoginConfiguredThenHasDefaultFailureUrl() throws Exception {
		this.spring.register(FormLoginConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("invalid")).andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?error"));
	}

	@Test
	public void loginWhenFormLoginConfiguredThenHasDefaultSuccessUrl() throws Exception {
		this.spring.register(FormLoginConfig.class).autowire();

		this.mockMvc.perform(formLogin()).andExpect(status().isFound()).andExpect(redirectedUrl("/"));
	}

	@Test
	public void getLoginPageWhenFormLoginConfiguredThenNotSecured() throws Exception {
		this.spring.register(FormLoginConfig.class).autowire();

		this.mockMvc.perform(get("/login")).andExpect(status().isFound());
	}

	@Test
	public void loginWhenFormLoginConfiguredThenSecured() throws Exception {
		this.spring.register(FormLoginConfig.class).autowire();

		this.mockMvc.perform(post("/login")).andExpect(status().isForbidden());
	}

	@Test
	public void requestProtectedWhenFormLoginConfiguredThenRedirectsToLogin() throws Exception {
		this.spring.register(FormLoginConfig.class).autowire();

		this.mockMvc.perform(get("/private")).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));
	}

	@EnableWebSecurity
	static class FormLoginConfig extends WebSecurityConfigurerAdapter {

		@Override
		public void configure(WebSecurity web) {
			// @formatter:off
			web
				.ignoring()
					.antMatchers("/resources/**");
			// @formatter:on
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.loginPage("/login");
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	@Test
	public void loginWhenFormLoginDefaultsInLambdaThenHasDefaultUsernameAndPasswordParameterNames() throws Exception {
		this.spring.register(FormLoginInLambdaConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("username", "user").password("password", "password"))
				.andExpect(status().isFound()).andExpect(redirectedUrl("/"));
	}

	@Test
	public void loginWhenFormLoginDefaultsInLambdaThenHasDefaultFailureUrl() throws Exception {
		this.spring.register(FormLoginInLambdaConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("invalid")).andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?error"));
	}

	@Test
	public void loginWhenFormLoginDefaultsInLambdaThenHasDefaultSuccessUrl() throws Exception {
		this.spring.register(FormLoginInLambdaConfig.class).autowire();

		this.mockMvc.perform(formLogin()).andExpect(status().isFound()).andExpect(redirectedUrl("/"));
	}

	@Test
	public void getLoginPageWhenFormLoginDefaultsInLambdaThenNotSecured() throws Exception {
		this.spring.register(FormLoginInLambdaConfig.class).autowire();

		this.mockMvc.perform(get("/login")).andExpect(status().isOk());
	}

	@Test
	public void loginWhenFormLoginDefaultsInLambdaThenSecured() throws Exception {
		this.spring.register(FormLoginInLambdaConfig.class).autowire();

		this.mockMvc.perform(post("/login")).andExpect(status().isForbidden());
	}

	@Test
	public void requestProtectedWhenFormLoginDefaultsInLambdaThenRedirectsToLogin() throws Exception {
		this.spring.register(FormLoginInLambdaConfig.class).autowire();

		this.mockMvc.perform(get("/private")).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));
	}

	@EnableWebSecurity
	static class FormLoginInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().hasRole("USER")
				)
				.formLogin(withDefaults());
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	@Test
	public void getLoginPageWhenFormLoginPermitAllThenPermittedAndNoRedirect() throws Exception {
		this.spring.register(FormLoginConfigPermitAll.class).autowire();

		this.mockMvc.perform(get("/login")).andExpect(status().isOk()).andExpect(redirectedUrl(null));
	}

	@Test
	public void getLoginPageWithErrorQueryWhenFormLoginPermitAllThenPermittedAndNoRedirect() throws Exception {
		this.spring.register(FormLoginConfigPermitAll.class).autowire();

		this.mockMvc.perform(get("/login?error")).andExpect(status().isOk()).andExpect(redirectedUrl(null));
	}

	@Test
	public void loginWhenFormLoginPermitAllAndInvalidUserThenRedirectsToLoginPageWithError() throws Exception {
		this.spring.register(FormLoginConfigPermitAll.class).autowire();

		this.mockMvc.perform(formLogin().user("invalid")).andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?error"));
	}

	@EnableWebSecurity
	static class FormLoginConfigPermitAll extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.permitAll();
			// @formatter:on
		}

	}

	@Test
	public void getLoginPageWhenCustomLoginPageThenPermittedAndNoRedirect() throws Exception {
		this.spring.register(FormLoginDefaultsConfig.class).autowire();

		this.mockMvc.perform(get("/authenticate")).andExpect(redirectedUrl(null));
	}

	@Test
	public void getLoginPageWithErrorQueryWhenCustomLoginPageThenPermittedAndNoRedirect() throws Exception {
		this.spring.register(FormLoginDefaultsConfig.class).autowire();

		this.mockMvc.perform(get("/authenticate?error")).andExpect(redirectedUrl(null));
	}

	@Test
	public void loginWhenCustomLoginPageAndInvalidUserThenRedirectsToCustomLoginPageWithError() throws Exception {
		this.spring.register(FormLoginDefaultsConfig.class).autowire();

		this.mockMvc.perform(formLogin("/authenticate").user("invalid")).andExpect(status().isFound())
				.andExpect(redirectedUrl("/authenticate?error"));
	}

	@Test
	public void logoutWhenCustomLoginPageThenRedirectsToCustomLoginPage() throws Exception {
		this.spring.register(FormLoginDefaultsConfig.class).autowire();

		this.mockMvc.perform(logout()).andExpect(redirectedUrl("/authenticate?logout"));
	}

	@Test
	public void getLoginPageWithLogoutQueryWhenCustomLoginPageThenPermittedAndNoRedirect() throws Exception {
		this.spring.register(FormLoginDefaultsConfig.class).autowire();

		this.mockMvc.perform(get("/authenticate?logout")).andExpect(redirectedUrl(null));
	}

	@EnableWebSecurity
	static class FormLoginDefaultsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.loginPage("/authenticate")
					.permitAll()
					.and()
				.logout()
					.permitAll();
			// @formatter:on
		}

	}

	@Test
	public void getLoginPageWhenCustomLoginPageInLambdaThenPermittedAndNoRedirect() throws Exception {
		this.spring.register(FormLoginDefaultsInLambdaConfig.class).autowire();

		this.mockMvc.perform(get("/authenticate")).andExpect(redirectedUrl(null));
	}

	@EnableWebSecurity
	static class FormLoginDefaultsInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().hasRole("USER")
				)
				.formLogin(formLogin ->
					formLogin
						.loginPage("/authenticate")
						.permitAll()
				)
				.logout(LogoutConfigurer::permitAll);
			// @formatter:on
		}

	}

	@Test
	public void loginWhenCustomLoginProcessingUrlThenRedirectsToHome() throws Exception {
		this.spring.register(FormLoginLoginProcessingUrlConfig.class).autowire();

		this.mockMvc.perform(formLogin("/loginCheck")).andExpect(status().isFound()).andExpect(redirectedUrl("/"));
	}

	@EnableWebSecurity
	static class FormLoginLoginProcessingUrlConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.formLogin()
					.loginProcessingUrl("/loginCheck")
					.loginPage("/login")
					.defaultSuccessUrl("/", true)
					.passwordParameter("password")
					.usernameParameter("username")
					.permitAll()
					.and()
				.logout()
					.logoutSuccessUrl("/login")
					.logoutUrl("/logout")
					.deleteCookies("JSESSIONID");
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	@Test
	public void loginWhenCustomLoginProcessingUrlInLambdaThenRedirectsToHome() throws Exception {
		this.spring.register(FormLoginLoginProcessingUrlInLambdaConfig.class).autowire();

		this.mockMvc.perform(formLogin("/loginCheck")).andExpect(status().isFound()).andExpect(redirectedUrl("/"));
	}

	@EnableWebSecurity
	static class FormLoginLoginProcessingUrlInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.formLogin(formLogin ->
					formLogin
						.loginProcessingUrl("/loginCheck")
						.loginPage("/login")
						.defaultSuccessUrl("/", true)
						.permitAll()
				)
				.logout(logout ->
					logout
						.logoutSuccessUrl("/login")
						.logoutUrl("/logout")
						.deleteCookies("JSESSIONID")
				);
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	@Test
	public void requestWhenCustomPortMapperThenPortMapperUsed() throws Exception {
		FormLoginUsesPortMapperConfig.PORT_MAPPER = mock(PortMapper.class);
		when(FormLoginUsesPortMapperConfig.PORT_MAPPER.lookupHttpsPort(any())).thenReturn(9443);
		this.spring.register(FormLoginUsesPortMapperConfig.class).autowire();

		this.mockMvc.perform(get("http://localhost:9090")).andExpect(status().isFound())
				.andExpect(redirectedUrl("https://localhost:9443/login"));

		verify(FormLoginUsesPortMapperConfig.PORT_MAPPER).lookupHttpsPort(any());
	}

	@EnableWebSecurity
	static class FormLoginUsesPortMapperConfig extends WebSecurityConfigurerAdapter {

		static PortMapper PORT_MAPPER;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.permitAll()
					.and()
				.portMapper()
					.portMapper(PORT_MAPPER);
			// @formatter:on
			LoginUrlAuthenticationEntryPoint authenticationEntryPoint = (LoginUrlAuthenticationEntryPoint) http
					.getConfigurer(FormLoginConfigurer.class).getAuthenticationEntryPoint();
			authenticationEntryPoint.setForceHttps(true);
		}

	}

	@Test
	public void failureUrlWhenPermitAllAndFailureHandlerThenSecured() throws Exception {
		this.spring.register(PermitAllIgnoresFailureHandlerConfig.class).autowire();

		this.mockMvc.perform(get("/login?error")).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));
	}

	@EnableWebSecurity
	static class PermitAllIgnoresFailureHandlerConfig extends WebSecurityConfigurerAdapter {

		static AuthenticationFailureHandler FAILURE_HANDLER = mock(AuthenticationFailureHandler.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.failureHandler(FAILURE_HANDLER)
					.permitAll();
			// @formatter:on
		}

	}

	@Test
	public void formLoginWhenInvokedTwiceThenUsesOriginalUsernameParameter() throws Exception {
		this.spring.register(DuplicateInvocationsDoesNotOverrideConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("custom-username", "user")).andExpect(authenticated());
	}

	@EnableWebSecurity
	static class DuplicateInvocationsDoesNotOverrideConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.usernameParameter("custom-username")
					.and()
				.formLogin();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	@Test
	public void loginWhenInvalidLoginAndFailureForwardUrlThenForwardsToFailureForwardUrl() throws Exception {
		this.spring.register(FormLoginUserForwardAuthenticationSuccessAndFailureConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("invalid")).andExpect(forwardedUrl("/failure_forward_url"));
	}

	@Test
	public void loginWhenSuccessForwardUrlThenForwardsToSuccessForwardUrl() throws Exception {
		this.spring.register(FormLoginUserForwardAuthenticationSuccessAndFailureConfig.class).autowire();

		this.mockMvc.perform(formLogin()).andExpect(forwardedUrl("/success_forward_url"));
	}

	@EnableWebSecurity
	static class FormLoginUserForwardAuthenticationSuccessAndFailureConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.disable()
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.formLogin()
					.failureForwardUrl("/failure_forward_url")
					.successForwardUrl("/success_forward_url")
					.permitAll();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnUsernamePasswordAuthenticationFilter() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor)
				.postProcess(any(UsernamePasswordAuthenticationFilter.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnLoginUrlAuthenticationEntryPoint() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(LoginUrlAuthenticationEntryPoint.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnExceptionTranslationFilter() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(ExceptionTranslationFilter.class));
	}

	@EnableWebSecurity
	static class ObjectPostProcessorConfig extends WebSecurityConfigurerAdapter {

		static ObjectPostProcessor<Object> objectPostProcessor;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.exceptionHandling()
					.and()
				.formLogin();
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

}
