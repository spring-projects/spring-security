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

import java.net.URI;
import java.util.Arrays;
import java.util.List;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.DeferredCsrfToken;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.RequestDataValueProcessor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.springframework.security.config.Customizer.withDefaults;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link CsrfConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 * @author Michael Vitz
 * @author Sam Simmons
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension.class)
public class CsrfConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void postWhenWebSecurityEnabledThenRespondsWithForbidden() throws Exception {
		this.spring
				.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();
		this.mvc.perform(post("/")).andExpect(status().isForbidden());
	}

	@Test
	public void putWhenWebSecurityEnabledThenRespondsWithForbidden() throws Exception {
		this.spring
				.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();
		this.mvc.perform(put("/")).andExpect(status().isForbidden());
	}

	@Test
	public void patchWhenWebSecurityEnabledThenRespondsWithForbidden() throws Exception {
		this.spring
				.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();
		this.mvc.perform(patch("/")).andExpect(status().isForbidden());
	}

	@Test
	public void deleteWhenWebSecurityEnabledThenRespondsWithForbidden() throws Exception {
		this.spring
				.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();
		this.mvc.perform(delete("/")).andExpect(status().isForbidden());
	}

	@Test
	public void invalidWhenWebSecurityEnabledThenRespondsWithForbidden() throws Exception {
		this.spring
				.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();
		this.mvc.perform(request("INVALID", URI.create("/"))).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenWebSecurityEnabledThenRespondsWithOk() throws Exception {
		this.spring
				.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();
		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	public void headWhenWebSecurityEnabledThenRespondsWithOk() throws Exception {
		this.spring
				.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();
		this.mvc.perform(head("/")).andExpect(status().isOk());
	}

	@Test
	public void traceWhenWebSecurityEnabledThenRespondsWithOk() throws Exception {
		this.spring
				.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();
		this.mvc.perform(request(HttpMethod.TRACE, "/")).andExpect(status().isOk());
	}

	@Test
	public void optionsWhenWebSecurityEnabledThenRespondsWithOk() throws Exception {
		this.spring
				.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class, BasicController.class)
				.autowire();
		this.mvc.perform(options("/")).andExpect(status().isOk());
	}

	@Test
	public void enableWebSecurityWhenDefaultConfigurationThenCreatesRequestDataValueProcessor() {
		this.spring.register(CsrfAppliedDefaultConfig.class, AllowHttpMethodsFirewallConfig.class).autowire();
		assertThat(this.spring.getContext().getBean(RequestDataValueProcessor.class)).isNotNull();
	}

	@Test
	public void postWhenCsrfDisabledThenRespondsWithOk() throws Exception {
		this.spring.register(DisableCsrfConfig.class, BasicController.class).autowire();
		this.mvc.perform(post("/")).andExpect(status().isOk());
	}

	@Test
	public void postWhenCsrfDisabledInLambdaThenRespondsWithOk() throws Exception {
		this.spring.register(DisableCsrfInLambdaConfig.class, BasicController.class).autowire();
		this.mvc.perform(post("/")).andExpect(status().isOk());
	}

	// SEC-2498
	@Test
	public void loginWhenCsrfDisabledThenRedirectsToPreviousPostRequest() throws Exception {
		this.spring.register(DisableCsrfEnablesRequestCacheConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(post("/to-save")).andReturn();
		RequestCache requestCache = new HttpSessionRequestCache();
		String redirectUrl = requestCache.getRequest(mvcResult.getRequest(), mvcResult.getResponse()).getRedirectUrl();
		this.mvc.perform(post("/login").param("username", "user").param("password", "password")
				.session((MockHttpSession) mvcResult.getRequest().getSession())).andExpect(status().isFound())
				.andExpect(redirectedUrl(redirectUrl));
	}

	@Test
	public void loginWhenCsrfEnabledThenDoesNotRedirectToPreviousPostRequest() throws Exception {
		CsrfDisablesPostRequestFromRequestCacheConfig.REPO = mock(CsrfTokenRepository.class);
		DefaultCsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token");
		given(CsrfDisablesPostRequestFromRequestCacheConfig.REPO.loadDeferredToken(any(HttpServletRequest.class),
				any(HttpServletResponse.class))).willReturn(new TestDeferredCsrfToken(csrfToken));
		this.spring.register(CsrfDisablesPostRequestFromRequestCacheConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(post("/some-url")).andReturn();
		this.mvc.perform(post("/login").param("username", "user").param("password", "password").with(csrf())
				.session((MockHttpSession) mvcResult.getRequest().getSession())).andExpect(status().isFound())
				.andExpect(redirectedUrl("/"));
		verify(CsrfDisablesPostRequestFromRequestCacheConfig.REPO, atLeastOnce())
				.loadDeferredToken(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void loginWhenCsrfEnabledThenRedirectsToPreviousGetRequest() throws Exception {
		CsrfDisablesPostRequestFromRequestCacheConfig.REPO = mock(CsrfTokenRepository.class);
		DefaultCsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token");
		given(CsrfDisablesPostRequestFromRequestCacheConfig.REPO.loadDeferredToken(any(HttpServletRequest.class),
				any(HttpServletResponse.class))).willReturn(new TestDeferredCsrfToken(csrfToken));
		this.spring.register(CsrfDisablesPostRequestFromRequestCacheConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/some-url")).andReturn();
		RequestCache requestCache = new HttpSessionRequestCache();
		String redirectUrl = requestCache.getRequest(mvcResult.getRequest(), mvcResult.getResponse()).getRedirectUrl();
		this.mvc.perform(post("/login").param("username", "user").param("password", "password").with(csrf())
				.session((MockHttpSession) mvcResult.getRequest().getSession())).andExpect(status().isFound())
				.andExpect(redirectedUrl(redirectUrl));
		verify(CsrfDisablesPostRequestFromRequestCacheConfig.REPO, atLeastOnce())
				.loadDeferredToken(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	// SEC-2422
	@Test
	public void postWhenCsrfEnabledAndSessionIsExpiredThenRespondsWithForbidden() throws Exception {
		this.spring.register(InvalidSessionUrlConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(post("/").param("_csrf", "abc")).andExpect(status().isFound())
				.andExpect(redirectedUrl("/error/sessionError")).andReturn();
		this.mvc.perform(post("/").session((MockHttpSession) mvcResult.getRequest().getSession()))
				.andExpect(status().isForbidden());
	}

	@Test
	public void requireCsrfProtectionMatcherWhenRequestDoesNotMatchThenRespondsWithOk() throws Exception {
		this.spring.register(RequireCsrfProtectionMatcherConfig.class, BasicController.class).autowire();
		given(RequireCsrfProtectionMatcherConfig.MATCHER.matches(any())).willReturn(false);
		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	public void requireCsrfProtectionMatcherWhenRequestMatchesThenRespondsWithForbidden() throws Exception {
		RequireCsrfProtectionMatcherConfig.MATCHER = mock(RequestMatcher.class);
		given(RequireCsrfProtectionMatcherConfig.MATCHER.matches(any())).willReturn(true);
		this.spring.register(RequireCsrfProtectionMatcherConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isForbidden());
	}

	@Test
	public void requireCsrfProtectionMatcherInLambdaWhenRequestDoesNotMatchThenRespondsWithOk() throws Exception {
		RequireCsrfProtectionMatcherInLambdaConfig.MATCHER = mock(RequestMatcher.class);
		this.spring.register(RequireCsrfProtectionMatcherInLambdaConfig.class, BasicController.class).autowire();
		given(RequireCsrfProtectionMatcherInLambdaConfig.MATCHER.matches(any())).willReturn(false);
		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	public void requireCsrfProtectionMatcherInLambdaWhenRequestMatchesThenRespondsWithForbidden() throws Exception {
		RequireCsrfProtectionMatcherInLambdaConfig.MATCHER = mock(RequestMatcher.class);
		given(RequireCsrfProtectionMatcherInLambdaConfig.MATCHER.matches(any())).willReturn(true);
		this.spring.register(RequireCsrfProtectionMatcherInLambdaConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isForbidden());
	}

	@Test
	public void postWhenCustomCsrfTokenRepositoryThenRepositoryIsUsed() throws Exception {
		CsrfTokenRepositoryConfig.REPO = mock(CsrfTokenRepository.class);
		given(CsrfTokenRepositoryConfig.REPO.loadDeferredToken(any(HttpServletRequest.class),
				any(HttpServletResponse.class)))
						.willReturn(new TestDeferredCsrfToken(new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token")));
		this.spring.register(CsrfTokenRepositoryConfig.class, BasicController.class).autowire();
		this.mvc.perform(post("/"));
		verify(CsrfTokenRepositoryConfig.REPO).loadDeferredToken(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void logoutWhenCustomCsrfTokenRepositoryThenCsrfTokenIsCleared() throws Exception {
		CsrfTokenRepositoryConfig.REPO = mock(CsrfTokenRepository.class);
		this.spring.register(CsrfTokenRepositoryConfig.class, BasicController.class).autowire();
		this.mvc.perform(post("/logout").with(csrf()).with(user("user")));
		verify(CsrfTokenRepositoryConfig.REPO).saveToken(isNull(), any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void loginWhenCustomCsrfTokenRepositoryThenCsrfTokenIsCleared() throws Exception {
		CsrfTokenRepositoryConfig.REPO = mock(CsrfTokenRepository.class);
		DefaultCsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token");
		given(CsrfTokenRepositoryConfig.REPO.loadToken(any())).willReturn(csrfToken);
		given(CsrfTokenRepositoryConfig.REPO.loadDeferredToken(any(HttpServletRequest.class),
				any(HttpServletResponse.class))).willReturn(new TestDeferredCsrfToken(csrfToken));
		this.spring.register(CsrfTokenRepositoryConfig.class, BasicController.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password");
		// @formatter:on
		this.mvc.perform(loginRequest).andExpect(redirectedUrl("/"));
		verify(CsrfTokenRepositoryConfig.REPO).loadToken(any(HttpServletRequest.class));
		verify(CsrfTokenRepositoryConfig.REPO).saveToken(isNull(), any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void getWhenCustomCsrfTokenRepositoryInLambdaThenRepositoryIsUsed() throws Exception {
		CsrfTokenRepositoryInLambdaConfig.REPO = mock(CsrfTokenRepository.class);
		given(CsrfTokenRepositoryInLambdaConfig.REPO.loadDeferredToken(any(HttpServletRequest.class),
				any(HttpServletResponse.class)))
						.willReturn(new TestDeferredCsrfToken(new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token")));
		this.spring.register(CsrfTokenRepositoryInLambdaConfig.class, BasicController.class).autowire();
		this.mvc.perform(post("/"));
		verify(CsrfTokenRepositoryInLambdaConfig.REPO).loadDeferredToken(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void getWhenCustomAccessDeniedHandlerThenHandlerIsUsed() throws Exception {
		AccessDeniedHandlerConfig.DENIED_HANDLER = mock(AccessDeniedHandler.class);
		this.spring.register(AccessDeniedHandlerConfig.class, BasicController.class).autowire();
		this.mvc.perform(post("/")).andExpect(status().isOk());
		verify(AccessDeniedHandlerConfig.DENIED_HANDLER).handle(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any());
	}

	@Test
	public void getWhenCustomDefaultAccessDeniedHandlerForThenHandlerIsUsed() throws Exception {
		DefaultAccessDeniedHandlerForConfig.DENIED_HANDLER = mock(AccessDeniedHandler.class);
		DefaultAccessDeniedHandlerForConfig.MATCHER = mock(RequestMatcher.class);
		given(DefaultAccessDeniedHandlerForConfig.MATCHER.matches(any())).willReturn(true);
		this.spring.register(DefaultAccessDeniedHandlerForConfig.class, BasicController.class).autowire();
		this.mvc.perform(post("/")).andExpect(status().isOk());
		verify(DefaultAccessDeniedHandlerForConfig.DENIED_HANDLER).handle(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any());
	}

	@Test
	public void loginWhenNoCsrfTokenThenRespondsWithForbidden() throws Exception {
		this.spring.register(FormLoginConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "password");
		this.mvc.perform(loginRequest)
				.andExpect(status().isForbidden())
				.andExpect(unauthenticated());
		// @formatter:on
	}

	@Test
	public void logoutWhenNoCsrfTokenThenRespondsWithForbidden() throws Exception {
		this.spring.register(FormLoginConfig.class).autowire();
		MockHttpServletRequestBuilder logoutRequest = post("/logout").with(user("username"));
		// @formatter:off
		this.mvc.perform(logoutRequest)
				.andExpect(status().isForbidden())
				.andExpect(authenticated());
		// @formatter:on
	}

	// SEC-2543
	@Test
	public void logoutWhenCsrfEnabledAndGetRequestThenDoesNotLogout() throws Exception {
		this.spring.register(FormLoginConfig.class).autowire();
		MockHttpServletRequestBuilder logoutRequest = get("/logout").with(user("username"));
		this.mvc.perform(logoutRequest).andExpect(authenticated());
	}

	@Test
	public void logoutWhenGetRequestAndGetEnabledForLogoutThenLogsOut() throws Exception {
		this.spring.register(LogoutAllowsGetConfig.class).autowire();
		MockHttpServletRequestBuilder logoutRequest = get("/logout").with(user("username"));
		this.mvc.perform(logoutRequest).andExpect(unauthenticated());
	}

	// SEC-2749
	@Test
	public void configureWhenRequireCsrfProtectionMatcherNullThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(NullRequireCsrfProtectionMatcherConfig.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void getWhenDefaultCsrfTokenRepositoryThenDoesNotCreateSession() throws Exception {
		this.spring.register(DefaultDoesNotCreateSession.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/")).andReturn();
		assertThat(mvcResult.getRequest().getSession(false)).isNull();
	}

	@Test
	public void getWhenNullAuthenticationStrategyThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(NullAuthenticationStrategy.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void csrfAuthenticationStrategyConfiguredThenStrategyUsed() throws Exception {
		CsrfAuthenticationStrategyConfig.STRATEGY = mock(SessionAuthenticationStrategy.class);
		this.spring.register(CsrfAuthenticationStrategyConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password");
		// @formatter:on
		this.mvc.perform(loginRequest).andExpect(redirectedUrl("/"));
		verify(CsrfAuthenticationStrategyConfig.STRATEGY, atLeastOnce()).onAuthentication(any(Authentication.class),
				any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void getLoginWhenCsrfTokenRequestAttributeHandlerSetThenRespondsWithNormalCsrfToken() throws Exception {
		CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token");
		given(csrfTokenRepository.loadDeferredToken(any(HttpServletRequest.class), any(HttpServletResponse.class)))
				.willReturn(new TestDeferredCsrfToken(csrfToken));
		CsrfTokenRequestHandlerConfig.REPO = csrfTokenRepository;
		CsrfTokenRequestHandlerConfig.HANDLER = new CsrfTokenRequestAttributeHandler();
		this.spring.register(CsrfTokenRequestHandlerConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/login")).andExpect(status().isOk())
				.andExpect(content().string(containsString(csrfToken.getToken())));
		verify(csrfTokenRepository).loadDeferredToken(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verifyNoMoreInteractions(csrfTokenRepository);
	}

	@Test
	public void loginWhenCsrfTokenRequestAttributeHandlerSetAndNormalCsrfTokenThenSuccess() throws Exception {
		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token");
		CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
		given(csrfTokenRepository.loadToken(any(HttpServletRequest.class))).willReturn(csrfToken);
		given(csrfTokenRepository.loadDeferredToken(any(HttpServletRequest.class), any(HttpServletResponse.class)))
				.willReturn(new TestDeferredCsrfToken(csrfToken));
		CsrfTokenRequestHandlerConfig.REPO = csrfTokenRepository;
		CsrfTokenRequestHandlerConfig.HANDLER = new CsrfTokenRequestAttributeHandler();
		this.spring.register(CsrfTokenRequestHandlerConfig.class, BasicController.class).autowire();

		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.header(csrfToken.getHeaderName(), csrfToken.getToken())
				.param("username", "user")
				.param("password", "password");
		// @formatter:on
		this.mvc.perform(loginRequest).andExpect(redirectedUrl("/"));
		verify(csrfTokenRepository).loadToken(any(HttpServletRequest.class));
		verify(csrfTokenRepository).saveToken(isNull(), any(HttpServletRequest.class), any(HttpServletResponse.class));
		verify(csrfTokenRepository, times(2)).loadDeferredToken(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
		verifyNoMoreInteractions(csrfTokenRepository);
	}

	@Test
	public void getLoginWhenXorCsrfTokenRequestAttributeHandlerSetThenRespondsWithMaskedCsrfToken() throws Exception {
		CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token");
		given(csrfTokenRepository.loadDeferredToken(any(HttpServletRequest.class), any(HttpServletResponse.class)))
				.willReturn(new TestDeferredCsrfToken(csrfToken));
		CsrfTokenRequestHandlerConfig.REPO = csrfTokenRepository;
		CsrfTokenRequestHandlerConfig.HANDLER = new XorCsrfTokenRequestAttributeHandler();
		this.spring.register(CsrfTokenRequestHandlerConfig.class, BasicController.class).autowire();
		this.mvc.perform(get("/login")).andExpect(status().isOk())
				.andExpect(content().string(not(containsString(csrfToken.getToken()))));
		verify(csrfTokenRepository).loadDeferredToken(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verifyNoMoreInteractions(csrfTokenRepository);
	}

	@Test
	public void loginWhenXorCsrfTokenRequestAttributeHandlerSetAndMaskedCsrfTokenThenSuccess() throws Exception {
		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token");
		CsrfTokenRepository csrfTokenRepository = mock(CsrfTokenRepository.class);
		given(csrfTokenRepository.loadToken(any(HttpServletRequest.class))).willReturn(csrfToken);
		given(csrfTokenRepository.loadDeferredToken(any(HttpServletRequest.class), any(HttpServletResponse.class)))
				.willReturn(new TestDeferredCsrfToken(csrfToken));
		CsrfTokenRequestHandlerConfig.REPO = csrfTokenRepository;
		CsrfTokenRequestHandlerConfig.HANDLER = new XorCsrfTokenRequestAttributeHandler();
		this.spring.register(CsrfTokenRequestHandlerConfig.class, BasicController.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/login")).andReturn();
		CsrfToken csrfTokenAttribute = (CsrfToken) mvcResult.getRequest().getAttribute(CsrfToken.class.getName());

		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.header(csrfToken.getHeaderName(), csrfTokenAttribute.getToken())
				.param("username", "user")
				.param("password", "password");
		// @formatter:on
		this.mvc.perform(loginRequest).andExpect(redirectedUrl("/"));
		verify(csrfTokenRepository).loadToken(any(HttpServletRequest.class));
		verify(csrfTokenRepository).saveToken(isNull(), any(HttpServletRequest.class), any(HttpServletResponse.class));
		verify(csrfTokenRepository, times(3)).loadDeferredToken(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
		verifyNoMoreInteractions(csrfTokenRepository);
	}

	@Test
	public void loginWhenFormLoginAndCookieCsrfTokenRepositorySetAndExistingTokenThenRemoves() throws Exception {
		CsrfToken csrfToken = new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "token");
		Cookie existingCookie = new Cookie("XSRF-TOKEN", csrfToken.getToken());
		CookieCsrfTokenRepository csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
		csrfTokenRepository.setCookieName(existingCookie.getName());
		CsrfTokenRequestHandlerConfig.REPO = csrfTokenRepository;
		CsrfTokenRequestHandlerConfig.HANDLER = new CsrfTokenRequestAttributeHandler();
		this.spring.register(CsrfTokenRequestHandlerConfig.class, BasicController.class).autowire();

		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.cookie(existingCookie)
				.header(csrfToken.getHeaderName(), csrfToken.getToken())
				.param("username", "user")
				.param("password", "password");
		// @formatter:on
		MvcResult mvcResult = this.mvc.perform(loginRequest).andExpect(redirectedUrl("/")).andReturn();
		List<Cookie> cookies = Arrays.asList(mvcResult.getResponse().getCookies());
		cookies.removeIf((cookie) -> !cookie.getName().equalsIgnoreCase(existingCookie.getName()));
		assertThat(cookies).hasSize(1);
		assertThat(cookies.get(0).getValue()).isEmpty();
	}

	@Test
	public void postWhenHttpBasicAndCookieCsrfTokenRepositorySetAndExistingTokenThenDoesNotGenerateNewToken()
			throws Exception {
		CsrfToken csrfToken = new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "token");
		Cookie existingCookie = new Cookie("XSRF-TOKEN", csrfToken.getToken());
		CookieCsrfTokenRepository csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
		csrfTokenRepository.setCookieName(existingCookie.getName());
		HttpBasicCsrfTokenRequestHandlerConfig.REPO = csrfTokenRepository;
		HttpBasicCsrfTokenRequestHandlerConfig.HANDLER = new CsrfTokenRequestAttributeHandler();
		this.spring.register(HttpBasicCsrfTokenRequestHandlerConfig.class, BasicController.class).autowire();

		HttpHeaders headers = new HttpHeaders();
		headers.set(csrfToken.getHeaderName(), csrfToken.getToken());
		headers.setBasicAuth("user", "password");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(post("/")
				.cookie(existingCookie)
				.headers(headers))
				.andExpect(status().isOk())
				.andReturn();
		// @formatter:on
		List<Cookie> cookies = Arrays.asList(mvcResult.getResponse().getCookies());
		cookies.removeIf((cookie) -> !cookie.getName().equalsIgnoreCase(existingCookie.getName()));
		assertThat(cookies).isEmpty();
	}

	@Test
	public void getWhenHttpBasicAndCookieCsrfTokenRepositorySetAndNoExistingCookieThenDoesNotGenerateNewToken()
			throws Exception {
		CsrfToken csrfToken = new DefaultCsrfToken("X-XSRF-TOKEN", "_csrf", "token");
		Cookie expectedCookie = new Cookie("XSRF-TOKEN", csrfToken.getToken());
		CookieCsrfTokenRepository csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
		csrfTokenRepository.setCookieName(expectedCookie.getName());
		HttpBasicCsrfTokenRequestHandlerConfig.REPO = csrfTokenRepository;
		HttpBasicCsrfTokenRequestHandlerConfig.HANDLER = new CsrfTokenRequestAttributeHandler();
		this.spring.register(HttpBasicCsrfTokenRequestHandlerConfig.class, BasicController.class).autowire();

		HttpHeaders headers = new HttpHeaders();
		headers.set(csrfToken.getHeaderName(), csrfToken.getToken());
		headers.setBasicAuth("user", "password");
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/")
				.headers(headers))
				.andExpect(status().isOk())
				.andReturn();
		// @formatter:on
		List<Cookie> cookies = Arrays.asList(mvcResult.getResponse().getCookies());
		cookies.removeIf((cookie) -> !cookie.getName().equalsIgnoreCase(expectedCookie.getName()));
		assertThat(cookies).isEmpty();
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

	@Configuration
	@EnableWebSecurity
	static class CsrfAppliedDefaultConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DisableCsrfConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.disable();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DisableCsrfInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf(AbstractHttpConfigurer::disable);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DisableCsrfEnablesRequestCacheConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
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
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CsrfDisablesPostRequestFromRequestCacheConfig {

		static CsrfTokenRepository REPO;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
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
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class InvalidSessionUrlConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.and()
				.sessionManagement()
					.invalidSessionUrl("/error/sessionError");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RequireCsrfProtectionMatcherConfig {

		static RequestMatcher MATCHER;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.requireCsrfProtectionMatcher(MATCHER);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RequireCsrfProtectionMatcherInLambdaConfig {

		static RequestMatcher MATCHER;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf((csrf) -> csrf.requireCsrfProtectionMatcher(MATCHER));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CsrfTokenRepositoryConfig {

		static CsrfTokenRepository REPO;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.csrf()
					.csrfTokenRepository(REPO);
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
	static class CsrfTokenRepositoryInLambdaConfig {

		static CsrfTokenRepository REPO;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin(withDefaults())
				.csrf((csrf) -> csrf.csrfTokenRepository(REPO));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AccessDeniedHandlerConfig {

		static AccessDeniedHandler DENIED_HANDLER;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.exceptionHandling()
					.accessDeniedHandler(DENIED_HANDLER);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultAccessDeniedHandlerForConfig {

		static AccessDeniedHandler DENIED_HANDLER;

		static RequestMatcher MATCHER;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.exceptionHandling()
					.defaultAccessDeniedHandlerFor(DENIED_HANDLER, MATCHER);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class FormLoginConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class LogoutAllowsGetConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.logout()
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NullRequireCsrfProtectionMatcherConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.requireCsrfProtectionMatcher(null);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultDoesNotCreateSession {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().permitAll()
					.and()
				.formLogin()
					.and()
				.httpBasic();
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
	static class NullAuthenticationStrategy {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.csrf()
					.sessionAuthenticationStrategy(null);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CsrfAuthenticationStrategyConfig {

		static SessionAuthenticationStrategy STRATEGY;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.formLogin()
					.and()
					.csrf()
					.sessionAuthenticationStrategy(STRATEGY);
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
	static class CsrfTokenRequestHandlerConfig {

		static CsrfTokenRepository REPO;

		static CsrfTokenRequestHandler HANDLER;

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize
					.anyRequest().authenticated()
				)
				.formLogin(Customizer.withDefaults())
				.csrf((csrf) -> csrf
					.csrfTokenRepository(REPO)
					.csrfTokenRequestHandler(HANDLER)
				);
			// @formatter:on

			return http.build();
		}

		@Autowired
		void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
					.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HttpBasicCsrfTokenRequestHandlerConfig {

		static CsrfTokenRepository REPO;

		static CsrfTokenRequestHandler HANDLER;

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize
					.anyRequest().authenticated()
				)
				.httpBasic(Customizer.withDefaults())
				.csrf((csrf) -> csrf
					.csrfTokenRepository(REPO)
					.csrfTokenRequestHandler(HANDLER)
				);
			// @formatter:on

			return http.build();
		}

		@Autowired
		void configure(AuthenticationManagerBuilder auth) throws Exception {
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
		void rootGet() {
		}

		@PostMapping("/")
		void rootPost() {
		}

	}

	private static final class TestDeferredCsrfToken implements DeferredCsrfToken {

		private final CsrfToken csrfToken;

		private TestDeferredCsrfToken(CsrfToken csrfToken) {
			this.csrfToken = csrfToken;
		}

		@Override
		public CsrfToken get() {
			return this.csrfToken;
		}

		@Override
		public boolean isGenerated() {
			return false;
		}

	}

}
