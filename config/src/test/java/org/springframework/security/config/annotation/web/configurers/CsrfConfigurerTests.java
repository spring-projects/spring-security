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
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.RequestDataValueProcessor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link CsrfConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
public class CsrfConfigurerTests {
	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void postWhenWebSecurityEnabledThenRespondsWithForbidden() throws Exception {
		this.spring.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();

		this.mvc.perform(post("/"))
				.andExpect(status().isForbidden());
	}

	@Test
	public void putWhenWebSecurityEnabledThenRespondsWithForbidden() throws Exception {
		this.spring.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();

		this.mvc.perform(put("/"))
				.andExpect(status().isForbidden());
	}

	@Test
	public void patchWhenWebSecurityEnabledThenRespondsWithForbidden() throws Exception {
		this.spring.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();

		this.mvc.perform(patch("/"))
				.andExpect(status().isForbidden());
	}

	@Test
	public void deleteWhenWebSecurityEnabledThenRespondsWithForbidden() throws Exception {
		this.spring.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();

		this.mvc.perform(delete("/"))
				.andExpect(status().isForbidden());
	}

	@Test
	public void invalidWhenWebSecurityEnabledThenRespondsWithForbidden() throws Exception {
		this.spring.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();

		this.mvc.perform(request("INVALID", URI.create("/")))
				.andExpect(status().isForbidden());
	}

	@Test
	public void getWhenWebSecurityEnabledThenRespondsWithOk() throws Exception {
		this.spring.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();

		this.mvc.perform(get("/"))
				.andExpect(status().isOk());
	}

	@Test
	public void headWhenWebSecurityEnabledThenRespondsWithOk() throws Exception {
		this.spring.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();

		this.mvc.perform(head("/"))
				.andExpect(status().isOk());
	}

	@Test
	public void traceWhenWebSecurityEnabledThenRespondsWithOk() throws Exception {
		this.spring.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();

		this.mvc.perform(request(HttpMethod.TRACE, "/"))
				.andExpect(status().isOk());
	}

	@Test
	public void optionsWhenWebSecurityEnabledThenRespondsWithOk() throws Exception {
		this.spring.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();

		this.mvc.perform(options("/"))
				.andExpect(status().isOk());
	}

	@Test
	public void enableWebSecurityWhenDefaultConfigurationThenCreatesRequestDataValueProcessor() {
		this.spring.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class).autowire();

		assertThat(this.spring.getContext().getBean(RequestDataValueProcessor.class)).isNotNull();
	}

	@Configuration
	static class AllowHttpMethodsFirewallConfig {
		@Bean
		StrictHttpFirewall strictHttpFirewall() {
			StrictHttpFirewall result = new StrictHttpFirewall();
			result.setUnsafeAllowAnyHttpMethod(true);
			return result;
		}
	}

	@EnableWebSecurity
	static class CsrfAppliedDefaultConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
		}
	}

	@Test
	public void postWhenCsrfDisabledThenRespondsWithOk() throws Exception {
		this.spring.register(DisableCsrfConfig.class, BasicController.class).autowire();

		this.mvc.perform(post("/"))
				.andExpect(status().isOk());
	}

	@EnableWebSecurity
	static class DisableCsrfConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.disable();
			// @formatter:on
		}
	}

	@Test
	public void postWhenCsrfDisabledInLambdaThenRespondsWithOk() throws Exception {
		this.spring.register(DisableCsrfInLambdaConfig.class, BasicController.class).autowire();

		this.mvc.perform(post("/"))
				.andExpect(status().isOk());
	}

	@EnableWebSecurity
	static class DisableCsrfInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf(AbstractHttpConfigurer::disable);
			// @formatter:on
		}
	}

	// SEC-2498
	@Test
	public void loginWhenCsrfDisabledThenRedirectsToPreviousPostRequest() throws Exception {
		this.spring.register(DisableCsrfEnablesRequestCacheConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(post("/to-save")).andReturn();

		this.mvc.perform(post("/login")
				.param("username", "user")
				.param("password", "password")
				.session((MockHttpSession) mvcResult.getRequest().getSession()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/to-save"));
	}

	@EnableWebSecurity
	static class DisableCsrfEnablesRequestCacheConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.formLogin()
					.and()
				.csrf()
					.disable();
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
	public void loginWhenCsrfEnabledThenDoesNotRedirectToPreviousPostRequest() throws Exception {
		CsrfDisablesPostRequestFromRequestCacheConfig.REPO = mock(CsrfTokenRepository.class);
		DefaultCsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token");
		when(CsrfDisablesPostRequestFromRequestCacheConfig.REPO.loadToken(any())).thenReturn(csrfToken);
		when(CsrfDisablesPostRequestFromRequestCacheConfig.REPO.generateToken(any())).thenReturn(csrfToken);
		this.spring.register(CsrfDisablesPostRequestFromRequestCacheConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(post("/some-url"))
				.andReturn();
		this.mvc.perform(post("/login")
				.param("username", "user")
				.param("password", "password")
				.with(csrf())
				.session((MockHttpSession) mvcResult.getRequest().getSession()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/"));

		verify(CsrfDisablesPostRequestFromRequestCacheConfig.REPO, atLeastOnce()).loadToken(any(HttpServletRequest.class));
	}

	@Test
	public void loginWhenCsrfEnabledThenRedirectsToPreviousGetRequest() throws Exception {
		CsrfDisablesPostRequestFromRequestCacheConfig.REPO = mock(CsrfTokenRepository.class);
		DefaultCsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token");
		when(CsrfDisablesPostRequestFromRequestCacheConfig.REPO.loadToken(any())).thenReturn(csrfToken);
		when(CsrfDisablesPostRequestFromRequestCacheConfig.REPO.generateToken(any())).thenReturn(csrfToken);
		this.spring.register(CsrfDisablesPostRequestFromRequestCacheConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/some-url"))
				.andReturn();
		this.mvc.perform(post("/login")
				.param("username", "user")
				.param("password", "password")
				.with(csrf())
				.session((MockHttpSession) mvcResult.getRequest().getSession()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/some-url"));

		verify(CsrfDisablesPostRequestFromRequestCacheConfig.REPO, atLeastOnce()).loadToken(any(HttpServletRequest.class));
	}

	@EnableWebSecurity
	static class CsrfDisablesPostRequestFromRequestCacheConfig extends WebSecurityConfigurerAdapter {
		static CsrfTokenRepository REPO;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.formLogin()
					.and()
				.csrf()
					.csrfTokenRepository(REPO);
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

	// SEC-2422
	@Test
	public void postWhenCsrfEnabledAndSessionIsExpiredThenRespondsWithForbidden() throws Exception {
		this.spring.register(InvalidSessionUrlConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(post("/")
				.param("_csrf", "abc"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/error/sessionError"))
				.andReturn();

		this.mvc.perform(post("/")
				.session((MockHttpSession) mvcResult.getRequest().getSession()))
				.andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class InvalidSessionUrlConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.and()
				.sessionManagement()
					.invalidSessionUrl("/error/sessionError");
			// @formatter:on
		}
	}

	@Test
	public void requireCsrfProtectionMatcherWhenRequestDoesNotMatchThenRespondsWithOk() throws Exception {
		this.spring.register(RequireCsrfProtectionMatcherConfig.class, BasicController.class).autowire();
		when(RequireCsrfProtectionMatcherConfig.MATCHER.matches(any()))
				.thenReturn(false);

		this.mvc.perform(get("/"))
				.andExpect(status().isOk());
	}

	@Test
	public void requireCsrfProtectionMatcherWhenRequestMatchesThenRespondsWithForbidden() throws Exception {
		RequireCsrfProtectionMatcherConfig.MATCHER = mock(RequestMatcher.class);
		when(RequireCsrfProtectionMatcherConfig.MATCHER.matches(any())).thenReturn(true);
		this.spring.register(RequireCsrfProtectionMatcherConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/"))
				.andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class RequireCsrfProtectionMatcherConfig extends WebSecurityConfigurerAdapter {
		static RequestMatcher MATCHER;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.requireCsrfProtectionMatcher(MATCHER);
			// @formatter:on
		}
	}

	@Test
	public void requireCsrfProtectionMatcherInLambdaWhenRequestDoesNotMatchThenRespondsWithOk() throws Exception {
		RequireCsrfProtectionMatcherInLambdaConfig.MATCHER = mock(RequestMatcher.class);
		this.spring.register(RequireCsrfProtectionMatcherInLambdaConfig.class, BasicController.class).autowire();
		when(RequireCsrfProtectionMatcherInLambdaConfig.MATCHER.matches(any()))
				.thenReturn(false);

		this.mvc.perform(get("/"))
				.andExpect(status().isOk());
	}

	@Test
	public void requireCsrfProtectionMatcherInLambdaWhenRequestMatchesThenRespondsWithForbidden() throws Exception {
		RequireCsrfProtectionMatcherInLambdaConfig.MATCHER = mock(RequestMatcher.class);
		when(RequireCsrfProtectionMatcherInLambdaConfig.MATCHER.matches(any())).thenReturn(true);
		this.spring.register(RequireCsrfProtectionMatcherInLambdaConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/"))
				.andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class RequireCsrfProtectionMatcherInLambdaConfig extends WebSecurityConfigurerAdapter {
		static RequestMatcher MATCHER;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf(csrf -> csrf.requireCsrfProtectionMatcher(MATCHER));
			// @formatter:on
		}
	}

	@Test
	public void getWhenCustomCsrfTokenRepositoryThenRepositoryIsUsed() throws Exception {
		CsrfTokenRepositoryConfig.REPO = mock(CsrfTokenRepository.class);
		when(CsrfTokenRepositoryConfig.REPO.loadToken(any()))
				.thenReturn(new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token"));
		this.spring.register(CsrfTokenRepositoryConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/"))
				.andExpect(status().isOk());
		verify(CsrfTokenRepositoryConfig.REPO).loadToken(any(HttpServletRequest.class));
	}

	@Test
	public void logoutWhenCustomCsrfTokenRepositoryThenCsrfTokenIsCleared() throws Exception {
		CsrfTokenRepositoryConfig.REPO = mock(CsrfTokenRepository.class);
		this.spring.register(CsrfTokenRepositoryConfig.class, BasicController.class).autowire();

		this.mvc.perform(post("/logout")
				.with(csrf())
				.with(user("user")));

		verify(CsrfTokenRepositoryConfig.REPO)
				.saveToken(isNull(), any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void loginWhenCustomCsrfTokenRepositoryThenCsrfTokenIsCleared() throws Exception {
		CsrfTokenRepositoryConfig.REPO = mock(CsrfTokenRepository.class);
		DefaultCsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token");
		when(CsrfTokenRepositoryConfig.REPO.loadToken(any())).thenReturn(csrfToken);
		when(CsrfTokenRepositoryConfig.REPO.generateToken(any())).thenReturn(csrfToken);
		this.spring.register(CsrfTokenRepositoryConfig.class, BasicController.class).autowire();

		this.mvc.perform(post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password"))
				.andExpect(redirectedUrl("/"));

		verify(CsrfTokenRepositoryConfig.REPO)
				.saveToken(isNull(), any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@EnableWebSecurity
	static class CsrfTokenRepositoryConfig extends WebSecurityConfigurerAdapter {
		static CsrfTokenRepository REPO;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.csrf()
					.csrfTokenRepository(REPO);
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
	public void getWhenCustomCsrfTokenRepositoryInLambdaThenRepositoryIsUsed() throws Exception {
		CsrfTokenRepositoryInLambdaConfig.REPO = mock(CsrfTokenRepository.class);
		when(CsrfTokenRepositoryInLambdaConfig.REPO.loadToken(any()))
				.thenReturn(new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token"));
		this.spring.register(CsrfTokenRepositoryInLambdaConfig.class, BasicController.class).autowire();

		this.mvc.perform(get("/"))
				.andExpect(status().isOk());
		verify(CsrfTokenRepositoryInLambdaConfig.REPO).loadToken(any(HttpServletRequest.class));
	}

	@EnableWebSecurity
	static class CsrfTokenRepositoryInLambdaConfig extends WebSecurityConfigurerAdapter {
		static CsrfTokenRepository REPO;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.csrf(csrf -> csrf.csrfTokenRepository(REPO));
			// @formatter:on
		}
	}

	@Test
	public void getWhenCustomAccessDeniedHandlerThenHandlerIsUsed() throws Exception {
		AccessDeniedHandlerConfig.DENIED_HANDLER = mock(AccessDeniedHandler.class);
		this.spring.register(AccessDeniedHandlerConfig.class, BasicController.class).autowire();

		this.mvc.perform(post("/"))
				.andExpect(status().isOk());

		verify(AccessDeniedHandlerConfig.DENIED_HANDLER)
				.handle(any(HttpServletRequest.class), any(HttpServletResponse.class), any());
	}

	@EnableWebSecurity
	static class AccessDeniedHandlerConfig extends WebSecurityConfigurerAdapter {
		static AccessDeniedHandler DENIED_HANDLER;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.exceptionHandling()
					.accessDeniedHandler(DENIED_HANDLER);
			// @formatter:on
		}
	}

	@Test
	public void loginWhenNoCsrfTokenThenRespondsWithForbidden() throws Exception {
		this.spring.register(FormLoginConfig.class).autowire();

		this.mvc.perform(post("/login")
				.param("username", "user")
				.param("password", "password"))
				.andExpect(status().isForbidden())
				.andExpect(unauthenticated());
	}

	@Test
	public void logoutWhenNoCsrfTokenThenRespondsWithForbidden() throws Exception {
		this.spring.register(FormLoginConfig.class).autowire();

		this.mvc.perform(post("/logout")
				.with(user("username")))
				.andExpect(status().isForbidden())
				.andExpect(authenticated());
	}

	// SEC-2543
	@Test
	public void logoutWhenCsrfEnabledAndGetRequestThenDoesNotLogout() throws Exception {
		this.spring.register(FormLoginConfig.class).autowire();

		this.mvc.perform(get("/logout")
				.with(user("username")))
				.andExpect(authenticated());
	}

	@EnableWebSecurity
	static class FormLoginConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin();
			// @formatter:on
		}
	}

	@Test
	public void logoutWhenGetRequestAndGetEnabledForLogoutThenLogsOut() throws Exception {
		this.spring.register(LogoutAllowsGetConfig.class).autowire();

		this.mvc.perform(get("/logout")
				.with(user("username")))
				.andExpect(unauthenticated());
	}

	@EnableWebSecurity
	static class LogoutAllowsGetConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.logout()
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
			// @formatter:on
		}
	}

	// SEC-2749
	@Test
	public void configureWhenRequireCsrfProtectionMatcherNullThenException() {
		assertThatThrownBy(() -> this.spring.register(NullRequireCsrfProtectionMatcherConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class)
				.hasRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@EnableWebSecurity
	static class NullRequireCsrfProtectionMatcherConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.requireCsrfProtectionMatcher(null);
			// @formatter:on
		}
	}

	@Test
	public void getWhenDefaultCsrfTokenRepositoryThenDoesNotCreateSession() throws Exception {
		this.spring.register(DefaultDoesNotCreateSession.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/"))
				.andReturn();

		assertThat(mvcResult.getRequest().getSession(false)).isNull();
	}

	@EnableWebSecurity
	static class DefaultDoesNotCreateSession extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.formLogin()
					.and()
				.httpBasic();
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

	@RestController
	static class BasicController {
		@GetMapping("/")
		public void rootGet() {
		}

		@PostMapping("/")
		public void rootPost() {
		}
	}
}
