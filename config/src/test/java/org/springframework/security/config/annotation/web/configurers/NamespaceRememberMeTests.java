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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests to verify that all the functionality of &lt;anonymous&gt; attributes is present
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
public class NamespaceRememberMeTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void rememberMeLoginWhenUsingDefaultsThenMatchesNamespace() throws Exception {
		this.spring.register(RememberMeConfig.class, SecurityController.class).autowire();
		MvcResult result = this.mvc.perform(post("/login").with(rememberMeLogin())).andReturn();

		MockHttpSession session = (MockHttpSession) result.getRequest().getSession();
		Cookie rememberMe = result.getResponse().getCookie("remember-me");
		assertThat(rememberMe).isNotNull();
		this.mvc.perform(get("/authentication-class").cookie(rememberMe))
				.andExpect(content().string(RememberMeAuthenticationToken.class.getName()));

		result = this.mvc.perform(post("/logout").with(csrf()).session(session).cookie(rememberMe))
				.andExpect(redirectedUrl("/login?logout")).andReturn();

		rememberMe = result.getResponse().getCookie("remember-me");
		assertThat(rememberMe).isNotNull().extracting(Cookie::getMaxAge).isEqualTo(0);

		this.mvc.perform(post("/authentication-class").with(csrf()).cookie(rememberMe))
				.andExpect(redirectedUrl("http://localhost/login")).andReturn();
	}

	// SEC-3170 - RememberMeService implementations should not have to also implement
	// LogoutHandler
	@Test
	public void logoutWhenCustomRememberMeServicesDeclaredThenUses() throws Exception {
		RememberMeServicesRefConfig.REMEMBER_ME_SERVICES = mock(RememberMeServicesWithoutLogoutHandler.class);
		this.spring.register(RememberMeServicesRefConfig.class).autowire();

		this.mvc.perform(get("/"));
		verify(RememberMeServicesRefConfig.REMEMBER_ME_SERVICES).autoLogin(any(HttpServletRequest.class),
				any(HttpServletResponse.class));

		this.mvc.perform(post("/login").with(csrf()));
		verify(RememberMeServicesRefConfig.REMEMBER_ME_SERVICES).loginFail(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void rememberMeLoginWhenAuthenticationSuccessHandlerDeclaredThenUses() throws Exception {
		AuthSuccessConfig.SUCCESS_HANDLER = mock(AuthenticationSuccessHandler.class);
		this.spring.register(AuthSuccessConfig.class).autowire();

		MvcResult result = this.mvc.perform(post("/login").with(rememberMeLogin())).andReturn();

		verifyZeroInteractions(AuthSuccessConfig.SUCCESS_HANDLER);

		Cookie rememberMe = result.getResponse().getCookie("remember-me");
		assertThat(rememberMe).isNotNull();
		this.mvc.perform(get("/somewhere").cookie(rememberMe));

		verify(AuthSuccessConfig.SUCCESS_HANDLER).onAuthenticationSuccess(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(Authentication.class));
	}

	@Test
	public void rememberMeLoginWhenKeyDeclaredThenMatchesNamespace() throws Exception {
		this.spring.register(WithoutKeyConfig.class, KeyConfig.class, SecurityController.class).autowire();
		Cookie withoutKey = this.mvc.perform(post("/without-key/login").with(rememberMeLogin()))
				.andExpect(redirectedUrl("/")).andReturn().getResponse().getCookie("remember-me");

		this.mvc.perform(get("/somewhere").cookie(withoutKey)).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));

		Cookie withKey = this.mvc.perform(post("/login").with(rememberMeLogin())).andReturn().getResponse()
				.getCookie("remember-me");
		this.mvc.perform(get("/somewhere").cookie(withKey)).andExpect(status().isNotFound());
	}

	// http/remember-me@services-alias is not supported use standard aliasing instead
	// (i.e. @Bean("alias"))

	// http/remember-me@data-source-ref is not supported directly. Instead use
	// http/remember-me@token-repository-ref example
	@Test
	public void rememberMeLoginWhenDeclaredTokenRepositoryThenMatchesNamespace() throws Exception {
		TokenRepositoryRefConfig.TOKEN_REPOSITORY = mock(PersistentTokenRepository.class);
		this.spring.register(TokenRepositoryRefConfig.class).autowire();

		this.mvc.perform(post("/login").with(rememberMeLogin()));

		verify(TokenRepositoryRefConfig.TOKEN_REPOSITORY).createNewToken(any(PersistentRememberMeToken.class));
	}

	@Test
	public void rememberMeLoginWhenTokenValidityDeclaredThenMatchesNamespace() throws Exception {
		this.spring.register(TokenValiditySecondsConfig.class).autowire();
		Cookie expiredRememberMe = this.mvc.perform(post("/login").with(rememberMeLogin())).andReturn().getResponse()
				.getCookie("remember-me");

		assertThat(expiredRememberMe).extracting(Cookie::getMaxAge).isEqualTo(314);
	}

	@Test
	public void rememberMeLoginWhenUsingDefaultsThenCookieMaxAgeMatchesNamespace() throws Exception {
		this.spring.register(RememberMeConfig.class).autowire();
		Cookie expiredRememberMe = this.mvc.perform(post("/login").with(rememberMeLogin())).andReturn().getResponse()
				.getCookie("remember-me");

		assertThat(expiredRememberMe).extracting(Cookie::getMaxAge).isEqualTo(AbstractRememberMeServices.TWO_WEEKS_S);
	}

	@Test
	public void rememberMeLoginWhenUsingSecureCookieThenMatchesNamespace() throws Exception {
		this.spring.register(UseSecureCookieConfig.class).autowire();
		Cookie secureCookie = this.mvc.perform(post("/login").with(rememberMeLogin())).andReturn().getResponse()
				.getCookie("remember-me");

		assertThat(secureCookie).extracting(Cookie::getSecure).isEqualTo(true);
	}

	@Test
	public void rememberMeLoginWhenUsingDefaultsThenCookieSecurityMatchesNamespace() throws Exception {
		this.spring.register(RememberMeConfig.class).autowire();
		Cookie secureCookie = this.mvc.perform(post("/login").with(rememberMeLogin()).secure(true)).andReturn()
				.getResponse().getCookie("remember-me");

		assertThat(secureCookie).extracting(Cookie::getSecure).isEqualTo(true);
	}

	@Test
	public void rememberMeLoginWhenParameterSpecifiedThenMatchesNamespace() throws Exception {
		this.spring.register(RememberMeParameterConfig.class).autowire();
		Cookie rememberMe = this.mvc.perform(post("/login").with(rememberMeLogin("rememberMe", true))).andReturn()
				.getResponse().getCookie("remember-me");

		assertThat(rememberMe).isNotNull();
	}

	// SEC-2880
	@Test
	public void rememberMeLoginWhenCookieNameDeclaredThenMatchesNamespace() throws Exception {
		this.spring.register(RememberMeCookieNameConfig.class).autowire();
		Cookie rememberMe = this.mvc.perform(post("/login").with(rememberMeLogin())).andReturn().getResponse()
				.getCookie("rememberMe");

		assertThat(rememberMe).isNotNull();
	}

	@Test
	public void rememberMeLoginWhenGlobalUserDetailsServiceDeclaredThenMatchesNamespace() throws Exception {
		DefaultsUserDetailsServiceWithDaoConfig.USERDETAILS_SERVICE = mock(UserDetailsService.class);
		this.spring.register(DefaultsUserDetailsServiceWithDaoConfig.class).autowire();

		this.mvc.perform(post("/login").with(rememberMeLogin()));

		verify(DefaultsUserDetailsServiceWithDaoConfig.USERDETAILS_SERVICE).loadUserByUsername("user");
	}

	@Test
	public void rememberMeLoginWhenUserDetailsServiceDeclaredThenMatchesNamespace() throws Exception {
		UserServiceRefConfig.USERDETAILS_SERVICE = mock(UserDetailsService.class);
		this.spring.register(UserServiceRefConfig.class).autowire();

		given(UserServiceRefConfig.USERDETAILS_SERVICE.loadUserByUsername("user"))
				.willReturn(new User("user", "password", AuthorityUtils.createAuthorityList("ROLE_USER")));

		this.mvc.perform(post("/login").with(rememberMeLogin()));

		verify(UserServiceRefConfig.USERDETAILS_SERVICE).loadUserByUsername("user");
	}

	static RequestPostProcessor rememberMeLogin() {
		return rememberMeLogin("remember-me", true);
	}

	static RequestPostProcessor rememberMeLogin(String parameterName, boolean parameterValue) {
		return request -> {
			csrf().postProcessRequest(request);
			request.setParameter("username", "user");
			request.setParameter("password", "password");
			request.setParameter(parameterName, String.valueOf(parameterValue));
			return request;
		};
	}

	@Configuration
	@EnableWebSecurity
	static class RememberMeConfig extends UsersConfig {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.and()
				.rememberMe();
			// @formatter:on
		}

	}

	interface RememberMeServicesWithoutLogoutHandler extends RememberMeServices {

	}

	@Configuration
	@EnableWebSecurity
	static class RememberMeServicesRefConfig extends WebSecurityConfigurerAdapter {

		static RememberMeServices REMEMBER_ME_SERVICES;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.rememberMe()
					.rememberMeServices(REMEMBER_ME_SERVICES);
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AuthSuccessConfig extends UsersConfig {

		static AuthenticationSuccessHandler SUCCESS_HANDLER;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.rememberMe()
					.authenticationSuccessHandler(SUCCESS_HANDLER);
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@Order(0)
	static class WithoutKeyConfig extends UsersConfig {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.antMatcher("/without-key/**")
					.formLogin()
						.loginProcessingUrl("/without-key/login")
						.and()
					.rememberMe();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class KeyConfig extends UsersConfig {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.formLogin()
					.and()
				.rememberMe()
					.key("KeyConfig");
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class TokenRepositoryRefConfig extends UsersConfig {

		static PersistentTokenRepository TOKEN_REPOSITORY;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl()
			// tokenRepository.setDataSource(dataSource);

			// @formatter:off
			http
				.formLogin()
					.and()
				.rememberMe()
					.tokenRepository(TOKEN_REPOSITORY);
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class TokenValiditySecondsConfig extends UsersConfig {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.formLogin()
					.and()
				.rememberMe()
					.tokenValiditySeconds(314);
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class UseSecureCookieConfig extends UsersConfig {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.rememberMe()
					.useSecureCookie(true);
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RememberMeParameterConfig extends UsersConfig {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.rememberMe()
					.rememberMeParameter("rememberMe");
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RememberMeCookieNameConfig extends UsersConfig {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.rememberMe()
					.rememberMeCookieName("rememberMe");
			// @formatter:on
		}

	}

	@EnableWebSecurity
	@Configuration
	static class DefaultsUserDetailsServiceWithDaoConfig extends WebSecurityConfigurerAdapter {

		static UserDetailsService USERDETAILS_SERVICE;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.rememberMe();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.userDetailsService(USERDETAILS_SERVICE);
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class UserServiceRefConfig extends UsersConfig {

		static UserDetailsService USERDETAILS_SERVICE;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.rememberMe()
					.userDetailsService(USERDETAILS_SERVICE);
			// @formatter:on
		}

	}

	static class UsersConfig extends WebSecurityConfigurerAdapter {

		@Override
		@Bean
		public UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
			// @formatter:off
					User.withDefaultPasswordEncoder()
							.username("user")
							.password("password")
							.roles("USER")
							.build());
					// @formatter:on
		}

	}

	@RestController
	static class SecurityController {

		@GetMapping("/authentication-class")
		String authenticationClass(Authentication authentication) {
			return authentication.getClass().getName();
		}

	}

}
