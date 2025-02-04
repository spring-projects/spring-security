/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.SmartApplicationListener;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.annotation.SecurityContextChangedListenerConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextChangedListener;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.TestOidcIdTokens;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.oidc.user.TestOidcUsers;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.session.HttpSessionDestroyedEvent;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.annotation.SecurityContextChangedListenerArgumentMatchers.setAuthentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

/**
 * Tests for {@link OAuth2LoginConfigurer}.
 *
 * @author Kazuki Shimizu
 * @author Joe Grandja
 * @since 5.0.1
 */
@ExtendWith(SpringTestContextExtension.class)
public class OAuth2LoginConfigurerTests {

	// @formatter:off
	private static final ClientRegistration GOOGLE_CLIENT_REGISTRATION = CommonOAuth2Provider.GOOGLE
			.getBuilder("google")
			.clientId("clientId")
			.clientSecret("clientSecret")
			.build();
	// @formatter:on

	// @formatter:off
	private static final ClientRegistration GITHUB_CLIENT_REGISTRATION = CommonOAuth2Provider.GITHUB
			.getBuilder("github")
			.clientId("clientId")
			.clientSecret("clientSecret")
			.build();
	// @formatter:on

	// @formatter:off
	private static final ClientRegistration CLIENT_CREDENTIALS_REGISTRATION = TestClientRegistrations.clientCredentials()
			.build();
	// @formatter:on

	private ConfigurableApplicationContext context;

	@Autowired
	private FilterChainProxy springSecurityFilterChain;

	@Autowired(required = false)
	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

	@Autowired(required = false)
	SecurityContextRepository securityContextRepository;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired(required = false)
	MockMvc mvc;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private MockFilterChain filterChain;

	@BeforeEach
	public void setup() {
		this.request = new MockHttpServletRequest("GET", "");
		this.request.setServletPath("/login/oauth2/code/google");
		this.response = new MockHttpServletResponse();
		this.filterChain = new MockFilterChain();
	}

	@AfterEach
	public void cleanup() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	public void oauth2Login() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfig.class);
		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, this.request, this.response);
		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());
		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		// assertions
		Authentication authentication = this.securityContextRepository
			.loadContext(new HttpRequestResponseHolder(this.request, this.response))
			.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(1);
		assertThat(authentication.getAuthorities()).first()
			.isInstanceOf(OAuth2UserAuthority.class)
			.hasToString("OAUTH2_USER");
	}

	@Test
	public void requestWhenCustomSecurityContextHolderStrategyThenUses() throws Exception {
		loadConfig(OAuth2LoginConfig.class, SecurityContextChangedListenerConfig.class);
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, this.request, this.response);
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		Authentication authentication = this.securityContextRepository
			.loadContext(new HttpRequestResponseHolder(this.request, this.response))
			.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(1);
		assertThat(authentication.getAuthorities()).first()
			.isInstanceOf(OAuth2UserAuthority.class)
			.hasToString("OAUTH2_USER");
		SecurityContextHolderStrategy strategy = this.context.getBean(SecurityContextHolderStrategy.class);
		verify(strategy, atLeastOnce()).getDeferredContext();
		SecurityContextChangedListener listener = this.context.getBean(SecurityContextChangedListener.class);
		verify(listener).securityContextChanged(setAuthentication(OAuth2AuthenticationToken.class));
	}

	@Test
	public void requestWhenOauth2LoginInLambdaThenAuthenticationContainsOauth2UserAuthority() throws Exception {
		loadConfig(OAuth2LoginInLambdaConfig.class);
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, this.request, this.response);
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		Authentication authentication = this.securityContextRepository
			.loadContext(new HttpRequestResponseHolder(this.request, this.response))
			.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(1);
		assertThat(authentication.getAuthorities()).first()
			.isInstanceOf(OAuth2UserAuthority.class)
			.hasToString("OAUTH2_USER");
	}

	// gh-6009
	@Test
	public void oauth2LoginWhenSuccessThenAuthenticationSuccessEventPublished() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfig.class);
		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, this.request, this.response);
		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());
		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		// assertions
		assertThat(OAuth2LoginConfig.EVENTS).isNotEmpty();
		assertThat(OAuth2LoginConfig.EVENTS).hasSize(1);
		assertThat(OAuth2LoginConfig.EVENTS.get(0)).isInstanceOf(AuthenticationSuccessEvent.class);
	}

	@Test
	public void oauth2LoginCustomWithConfigurer() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfigCustomWithConfigurer.class);
		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, this.request, this.response);
		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());
		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		// assertions
		Authentication authentication = this.securityContextRepository
			.loadContext(new HttpRequestResponseHolder(this.request, this.response))
			.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(2);
		assertThat(authentication.getAuthorities()).first().hasToString("OAUTH2_USER");
		assertThat(authentication.getAuthorities()).last().hasToString("ROLE_OAUTH2_USER");
	}

	@Test
	public void oauth2LoginCustomWithBeanRegistration() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfigCustomWithBeanRegistration.class);
		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, this.request, this.response);
		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());
		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		// assertions
		Authentication authentication = this.securityContextRepository
			.loadContext(new HttpRequestResponseHolder(this.request, this.response))
			.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(2);
		assertThat(authentication.getAuthorities()).first().hasToString("OAUTH2_USER");
		assertThat(authentication.getAuthorities()).last().hasToString("ROLE_OAUTH2_USER");
	}

	@Test
	public void oauth2LoginCustomWithUserServiceBeanRegistration() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfigCustomUserServiceBeanRegistration.class);
		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, this.request, this.response);
		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());
		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		// assertions
		Authentication authentication = this.securityContextRepository
			.loadContext(new HttpRequestResponseHolder(this.request, this.response))
			.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(2);
		assertThat(authentication.getAuthorities()).first().hasToString("OAUTH2_USER");
		assertThat(authentication.getAuthorities()).last().hasToString("ROLE_OAUTH2_USER");
	}

	// gh-5488
	@Test
	public void oauth2LoginConfigLoginProcessingUrl() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfigLoginProcessingUrl.class);
		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest();
		this.request.setServletPath("/login/oauth2/google");
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, this.request, this.response);
		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());
		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		// assertions
		Authentication authentication = this.securityContextRepository
			.loadContext(new HttpRequestResponseHolder(this.request, this.response))
			.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(1);
		assertThat(authentication.getAuthorities()).first()
			.isInstanceOf(OAuth2UserAuthority.class)
			.hasToString("OAUTH2_USER");
	}

	// gh-5521
	@Test
	public void oauth2LoginWithCustomAuthorizationRequestParameters() throws Exception {
		loadConfig(OAuth2LoginConfigCustomAuthorizationRequestResolver.class);
		OAuth2AuthorizationRequestResolver resolver = this.context
			.getBean(OAuth2LoginConfigCustomAuthorizationRequestResolver.class).resolver;
		// @formatter:off
		OAuth2AuthorizationRequest result = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://accounts.google.com/authorize")
				.clientId("client-id")
				.state("adsfa")
				.authorizationRequestUri(
						"https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=clientId&scope=openid+profile+email&state=state&redirect_uri=http%3A%2F%2Flocalhost%2Flogin%2Foauth2%2Fcode%2Fgoogle&custom-param1=custom-value1")
				.build();
		// @formatter:on
		given(resolver.resolve(any())).willReturn(result);
		String requestUri = "/oauth2/authorization/google";
		this.request = new MockHttpServletRequest("GET", requestUri);
		this.request.setServletPath(requestUri);
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getRedirectedUrl()).isEqualTo(
				"https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=clientId&scope=openid+profile+email&state=state&redirect_uri=http%3A%2F%2Flocalhost%2Flogin%2Foauth2%2Fcode%2Fgoogle&custom-param1=custom-value1");
	}

	@Test
	public void requestWhenOauth2LoginWithCustomAuthorizationRequestParametersThenParametersInRedirectedUrl()
			throws Exception {
		loadConfig(OAuth2LoginConfigCustomAuthorizationRequestResolverInLambda.class);
		OAuth2AuthorizationRequestResolver resolver = this.context
			.getBean(OAuth2LoginConfigCustomAuthorizationRequestResolverInLambda.class).resolver;
		// @formatter:off
		OAuth2AuthorizationRequest result = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://accounts.google.com/authorize")
				.clientId("client-id")
				.state("adsfa")
				.authorizationRequestUri(
						"https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=clientId&scope=openid+profile+email&state=state&redirect_uri=http%3A%2F%2Flocalhost%2Flogin%2Foauth2%2Fcode%2Fgoogle&custom-param1=custom-value1")
				.build();
		// @formatter:on
		given(resolver.resolve(any())).willReturn(result);
		String requestUri = "/oauth2/authorization/google";
		this.request = new MockHttpServletRequest("GET", requestUri);
		this.request.setServletPath(requestUri);
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getRedirectedUrl()).isEqualTo(
				"https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=clientId&scope=openid+profile+email&state=state&redirect_uri=http%3A%2F%2Flocalhost%2Flogin%2Foauth2%2Fcode%2Fgoogle&custom-param1=custom-value1");
	}

	@Test
	public void oauth2LoginWithAuthorizationRedirectStrategyThenCustomAuthorizationRedirectStrategyUsed()
			throws Exception {
		loadConfig(OAuth2LoginConfigCustomAuthorizationRedirectStrategy.class);
		RedirectStrategy redirectStrategy = this.context
			.getBean(OAuth2LoginConfigCustomAuthorizationRedirectStrategy.class).redirectStrategy;
		String requestUri = "/oauth2/authorization/google";
		this.request = new MockHttpServletRequest("GET", requestUri);
		this.request.setServletPath(requestUri);
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		then(redirectStrategy).should().sendRedirect(any(), any(), anyString());
	}

	@Test
	public void requestWhenOauth2LoginWithCustomAuthorizationRedirectStrategyThenCustomAuthorizationRedirectStrategyUsed()
			throws Exception {
		loadConfig(OAuth2LoginConfigCustomAuthorizationRedirectStrategyInLambda.class);
		RedirectStrategy redirectStrategy = this.context
			.getBean(OAuth2LoginConfigCustomAuthorizationRedirectStrategyInLambda.class).redirectStrategy;
		String requestUri = "/oauth2/authorization/google";
		this.request = new MockHttpServletRequest("GET", requestUri);
		this.request.setServletPath(requestUri);
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		then(redirectStrategy).should().sendRedirect(any(), any(), anyString());
	}

	// gh-5347
	@Test
	public void oauth2LoginWithOneClientConfiguredThenRedirectForAuthorization() throws Exception {
		loadConfig(OAuth2LoginConfig.class);
		String requestUri = "/";
		this.request = new MockHttpServletRequest("GET", requestUri);
		this.request.setServletPath(requestUri);
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getRedirectedUrl()).matches("http://localhost/oauth2/authorization/google");
	}

	// gh-6802
	@Test
	public void oauth2LoginWithOneClientConfiguredAndFormLoginThenRedirectDefaultLoginPage() throws Exception {
		loadConfig(OAuth2LoginConfigFormLogin.class);
		String requestUri = "/";
		this.request = new MockHttpServletRequest("GET", requestUri);
		this.request.setServletPath(requestUri);
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getRedirectedUrl()).matches("http://localhost/login");
	}

	// gh-5347
	@Test
	public void oauth2LoginWithOneClientConfiguredAndRequestFaviconNotAuthenticatedThenRedirectDefaultLoginPage()
			throws Exception {
		loadConfig(OAuth2LoginConfig.class);
		String requestUri = "/favicon.ico";
		this.request = new MockHttpServletRequest("GET", requestUri);
		this.request.setServletPath(requestUri);
		this.request.addHeader(HttpHeaders.ACCEPT, new MediaType("image", "*").toString());
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getRedirectedUrl()).matches("http://localhost/login");
	}

	// gh-5347
	@Test
	public void oauth2LoginWithMultipleClientsConfiguredThenRedirectDefaultLoginPage() throws Exception {
		loadConfig(OAuth2LoginConfigMultipleClients.class);
		String requestUri = "/";
		this.request = new MockHttpServletRequest("GET", requestUri);
		this.request.setServletPath(requestUri);
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getRedirectedUrl()).matches("http://localhost/login");
	}

	// gh-6812
	@Test
	public void oauth2LoginWithOneClientConfiguredAndRequestXHRNotAuthenticatedThenDoesNotRedirectForAuthorization()
			throws Exception {
		loadConfig(OAuth2LoginConfig.class);
		String requestUri = "/";
		this.request = new MockHttpServletRequest("GET", requestUri);
		this.request.setServletPath(requestUri);
		this.request.addHeader("X-Requested-With", "XMLHttpRequest");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getRedirectedUrl()).doesNotMatch("http://localhost/oauth2/authorization/google");
	}

	@Test
	public void oauth2LoginWithHttpBasicOneClientConfiguredAndRequestXHRNotAuthenticatedThenUnauthorized()
			throws Exception {
		loadConfig(OAuth2LoginWithHttpBasicConfig.class);
		String requestUri = "/";
		this.request = new MockHttpServletRequest("GET", requestUri);
		this.request.setServletPath(requestUri);
		this.request.addHeader("X-Requested-With", "XMLHttpRequest");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getStatus()).isEqualTo(401);
	}

	@Test
	public void oauth2LoginWithXHREntryPointOneClientConfiguredAndRequestXHRNotAuthenticatedThenUnauthorized()
			throws Exception {
		loadConfig(OAuth2LoginWithXHREntryPointConfig.class);
		String requestUri = "/";
		this.request = new MockHttpServletRequest("GET", requestUri);
		this.request.setServletPath(requestUri);
		this.request.addHeader("X-Requested-With", "XMLHttpRequest");
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getStatus()).isEqualTo(401);
	}

	// gh-9457
	@Test
	public void oauth2LoginWithOneAuthorizationCodeClientAndOtherClientsConfiguredThenRedirectForAuthorization()
			throws Exception {
		loadConfig(OAuth2LoginConfigAuthorizationCodeClientAndOtherClients.class);
		String requestUri = "/";
		this.request = new MockHttpServletRequest("GET", requestUri);
		this.request.setServletPath(requestUri);
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getRedirectedUrl()).matches("http://localhost/oauth2/authorization/google");
	}

	@Test
	public void oauth2LoginWithCustomLoginPageThenRedirectCustomLoginPage() throws Exception {
		loadConfig(OAuth2LoginConfigCustomLoginPage.class);
		String requestUri = "/";
		this.request = new MockHttpServletRequest("GET", requestUri);
		this.request.setServletPath(requestUri);
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getRedirectedUrl()).matches("http://localhost/custom-login");
	}

	@Test
	public void requestWhenOauth2LoginWithCustomLoginPageInLambdaThenRedirectCustomLoginPage() throws Exception {
		loadConfig(OAuth2LoginConfigCustomLoginPageInLambda.class);
		String requestUri = "/";
		this.request = new MockHttpServletRequest("GET", requestUri);
		this.request.setServletPath(requestUri);
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getRedirectedUrl()).matches("http://localhost/custom-login");
	}

	@Test
	public void oidcLogin() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfig.class, JwtDecoderFactoryConfig.class);
		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest("openid");
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, this.request, this.response);
		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());
		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		// assertions
		Authentication authentication = this.securityContextRepository
			.loadContext(new HttpRequestResponseHolder(this.request, this.response))
			.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(1);
		assertThat(authentication.getAuthorities()).first()
			.isInstanceOf(OidcUserAuthority.class)
			.hasToString("OIDC_USER");
	}

	@Test
	public void requestWhenOauth2LoginInLambdaAndOidcThenAuthenticationContainsOidcUserAuthority() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginInLambdaConfig.class, JwtDecoderFactoryConfig.class);
		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest("openid");
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, this.request, this.response);
		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());
		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		// assertions
		Authentication authentication = this.securityContextRepository
			.loadContext(new HttpRequestResponseHolder(this.request, this.response))
			.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(1);
		assertThat(authentication.getAuthorities()).first()
			.isInstanceOf(OidcUserAuthority.class)
			.hasToString("OIDC_USER");
	}

	@Test
	public void oidcLoginCustomWithConfigurer() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfigCustomWithConfigurer.class, JwtDecoderFactoryConfig.class);
		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest("openid");
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, this.request, this.response);
		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());
		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		// assertions
		Authentication authentication = this.securityContextRepository
			.loadContext(new HttpRequestResponseHolder(this.request, this.response))
			.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(2);
		assertThat(authentication.getAuthorities()).first().hasToString("OIDC_USER");
		assertThat(authentication.getAuthorities()).last().hasToString("ROLE_OIDC_USER");
	}

	@Test
	public void oidcLoginCustomWithBeanRegistration() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfigCustomWithBeanRegistration.class, JwtDecoderFactoryConfig.class);
		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest("openid");
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, this.request, this.response);
		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());
		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);
		// assertions
		Authentication authentication = this.securityContextRepository
			.loadContext(new HttpRequestResponseHolder(this.request, this.response))
			.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(2);
		assertThat(authentication.getAuthorities()).first().hasToString("OIDC_USER");
		assertThat(authentication.getAuthorities()).last().hasToString("ROLE_OIDC_USER");
	}

	@Test
	public void oidcLoginCustomWithNoUniqueJwtDecoderFactory() {
		assertThatExceptionOfType(BeanCreationException.class)
			.isThrownBy(() -> loadConfig(OAuth2LoginConfig.class, NoUniqueJwtDecoderFactoryConfig.class))
			.withRootCauseInstanceOf(NoUniqueBeanDefinitionException.class)
			.withMessageContaining("No qualifying bean of type "
					+ "'org.springframework.security.oauth2.jwt.JwtDecoderFactory<org.springframework.security.oauth2.client.registration.ClientRegistration>' "
					+ "available: expected single matching bean but found 2: jwtDecoderFactory1,jwtDecoderFactory2");
	}

	@Test
	public void logoutWhenUsingOidcLogoutHandlerThenRedirects() throws Exception {
		this.spring.register(OAuth2LoginConfigWithOidcLogoutSuccessHandler.class).autowire();
		OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(TestOidcUsers.create(),
				AuthorityUtils.NO_AUTHORITIES, "registration-id");
		this.mvc.perform(post("/logout").with(authentication(token)).with(csrf()))
			.andExpect(redirectedUrl("https://logout?id_token_hint=id-token"));
	}

	@Test
	public void configureWhenOidcSessionRegistryThenUses() {
		this.spring.register(OAuth2LoginWithOidcSessionRegistry.class).autowire();
		OidcSessionRegistry registry = this.spring.getContext().getBean(OidcSessionRegistry.class);
		this.spring.getContext().publishEvent(new HttpSessionDestroyedEvent(this.request.getSession()));
		verify(registry).removeSessionInformation(this.request.getSession().getId());
	}

	// gh-14558
	@Test
	public void oauth2LoginWhenDefaultsThenNoOidcSessionRegistry() {
		this.spring.register(OAuth2LoginConfig.class).autowire();
		DelegatingApplicationListener listener = this.spring.getContext().getBean(DelegatingApplicationListener.class);
		List<SmartApplicationListener> listeners = (List<SmartApplicationListener>) ReflectionTestUtils
			.getField(listener, "listeners");
		assertThat(listeners.stream()
			.filter((l) -> l.supportsEventType(SessionDestroyedEvent.class))
			.collect(Collectors.toList())).isEmpty();
	}

	private void loadConfig(Class<?>... configs) {
		AnnotationConfigWebApplicationContext applicationContext = new AnnotationConfigWebApplicationContext();
		applicationContext.register(configs);
		applicationContext.refresh();
		applicationContext.getAutowireCapableBeanFactory().autowireBean(this);
		this.context = applicationContext;
	}

	private OAuth2AuthorizationRequest createOAuth2AuthorizationRequest(String... scopes) {
		return this.createOAuth2AuthorizationRequest(GOOGLE_CLIENT_REGISTRATION, scopes);
	}

	private OAuth2AuthorizationRequest createOAuth2AuthorizationRequest(ClientRegistration registration,
			String... scopes) {
		// @formatter:off
		return OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(registration.getProviderDetails().getAuthorizationUri())
				.clientId(registration.getClientId())
				.state("state123")
				.redirectUri("http://localhost")
				.attributes(Collections.singletonMap(OAuth2ParameterNames.REGISTRATION_ID,
						registration.getRegistrationId()))
				.scope(scopes)
				.build();
		// @formatter:on
	}

	private static OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> createOauth2AccessTokenResponseClient() {
		return (request) -> {
			Map<String, Object> additionalParameters = new HashMap<>();
			if (request.getAuthorizationExchange().getAuthorizationRequest().getScopes().contains("openid")) {
				additionalParameters.put(OidcParameterNames.ID_TOKEN, "token123");
			}
			return OAuth2AccessTokenResponse.withToken("accessToken123")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.additionalParameters(additionalParameters)
				.build();
		};
	}

	private static OAuth2UserService<OAuth2UserRequest, OAuth2User> createOauth2UserService() {
		Map<String, Object> userAttributes = Collections.singletonMap("name", "spring");
		return (request) -> new DefaultOAuth2User(Collections.singleton(new OAuth2UserAuthority(userAttributes)),
				userAttributes, "name");
	}

	private static OAuth2UserService<OidcUserRequest, OidcUser> createOidcUserService() {
		OidcIdToken idToken = TestOidcIdTokens.idToken().build();
		return (request) -> new DefaultOidcUser(Collections.singleton(new OidcUserAuthority(idToken)), idToken);
	}

	private static GrantedAuthoritiesMapper createGrantedAuthoritiesMapper() {
		return (authorities) -> {
			boolean isOidc = OidcUserAuthority.class.isInstance(authorities.iterator().next());
			List<GrantedAuthority> mappedAuthorities = new ArrayList<>(authorities);
			mappedAuthorities.add(new SimpleGrantedAuthority(isOidc ? "ROLE_OIDC_USER" : "ROLE_OAUTH2_USER"));
			return mappedAuthorities;
		};
	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginConfig extends CommonSecurityFilterChainConfig
			implements ApplicationListener<AuthenticationSuccessEvent> {

		static List<AuthenticationSuccessEvent> EVENTS = new ArrayList<>();

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2Login()
					.clientRegistrationRepository(
						new InMemoryClientRegistrationRepository(GOOGLE_CLIENT_REGISTRATION));
			// @formatter:on
			return super.configureFilterChain(http);
		}

		@Override
		public void onApplicationEvent(AuthenticationSuccessEvent event) {
			EVENTS.add(event);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginConfigFormLogin extends CommonSecurityFilterChainConfig {

		private final InMemoryClientRegistrationRepository clientRegistrationRepository = new InMemoryClientRegistrationRepository(
				GOOGLE_CLIENT_REGISTRATION);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2Login()
					.clientRegistrationRepository(this.clientRegistrationRepository)
					.and()
				.formLogin();
			// @formatter:on
			return super.configureFilterChain(http);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginInLambdaConfig extends CommonLambdaSecurityFilterChainConfig
			implements ApplicationListener<AuthenticationSuccessEvent> {

		static List<AuthenticationSuccessEvent> EVENTS = new ArrayList<>();

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2Login((oauth2Login) ->
					oauth2Login
						.clientRegistrationRepository(
							new InMemoryClientRegistrationRepository(GOOGLE_CLIENT_REGISTRATION))
				);
			// @formatter:on
			return super.configureFilterChain(http);
		}

		@Override
		public void onApplicationEvent(AuthenticationSuccessEvent event) {
			EVENTS.add(event);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginConfigCustomWithConfigurer extends CommonSecurityFilterChainConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2Login()
					.clientRegistrationRepository(
							new InMemoryClientRegistrationRepository(GOOGLE_CLIENT_REGISTRATION))
					.userInfoEndpoint()
						.userAuthoritiesMapper(createGrantedAuthoritiesMapper());
			// @formatter:on
			return super.configureFilterChain(http);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginConfigCustomWithBeanRegistration extends CommonSecurityFilterChainConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2Login();
			// @formatter:on
			return super.configureFilterChain(http);
		}

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return new InMemoryClientRegistrationRepository(GOOGLE_CLIENT_REGISTRATION);
		}

		@Bean
		GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
			return createGrantedAuthoritiesMapper();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginConfigCustomUserServiceBeanRegistration {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.securityContext()
					.securityContextRepository(securityContextRepository())
					.and()
				.oauth2Login()
					.tokenEndpoint()
						.accessTokenResponseClient(createOauth2AccessTokenResponseClient());
			return http.build();
			// @formatter:on
		}

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return new InMemoryClientRegistrationRepository(GOOGLE_CLIENT_REGISTRATION);
		}

		@Bean
		GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
			return createGrantedAuthoritiesMapper();
		}

		@Bean
		SecurityContextRepository securityContextRepository() {
			return new HttpSessionSecurityContextRepository();
		}

		@Bean
		HttpSessionOAuth2AuthorizationRequestRepository oauth2AuthorizationRequestRepository() {
			return new HttpSessionOAuth2AuthorizationRequestRepository();
		}

		@Bean
		OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
			return createOauth2UserService();
		}

		@Bean
		OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
			return createOidcUserService();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginConfigLoginProcessingUrl extends CommonSecurityFilterChainConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2Login()
					.clientRegistrationRepository(
						new InMemoryClientRegistrationRepository(GOOGLE_CLIENT_REGISTRATION))
					.loginProcessingUrl("/login/oauth2/*");
			// @formatter:on
			return super.configureFilterChain(http);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginConfigCustomAuthorizationRequestResolver extends CommonSecurityFilterChainConfig {

		private ClientRegistrationRepository clientRegistrationRepository = new InMemoryClientRegistrationRepository(
				GOOGLE_CLIENT_REGISTRATION);

		OAuth2AuthorizationRequestResolver resolver = mock(OAuth2AuthorizationRequestResolver.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2Login()
					.clientRegistrationRepository(this.clientRegistrationRepository)
					.authorizationEndpoint()
						.authorizationRequestResolver(this.resolver);
			// @formatter:on
			return super.configureFilterChain(http);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginConfigCustomAuthorizationRequestResolverInLambda
			extends CommonLambdaSecurityFilterChainConfig {

		private ClientRegistrationRepository clientRegistrationRepository = new InMemoryClientRegistrationRepository(
				GOOGLE_CLIENT_REGISTRATION);

		OAuth2AuthorizationRequestResolver resolver = mock(OAuth2AuthorizationRequestResolver.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2Login((oauth2Login) ->
					oauth2Login
						.clientRegistrationRepository(this.clientRegistrationRepository)
						.authorizationEndpoint((authorizationEndpoint) ->
							authorizationEndpoint
								.authorizationRequestResolver(this.resolver)
						)
				);
			// @formatter:on
			return super.configureFilterChain(http);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginConfigCustomAuthorizationRedirectStrategy extends CommonSecurityFilterChainConfig {

		private final ClientRegistrationRepository clientRegistrationRepository = new InMemoryClientRegistrationRepository(
				GOOGLE_CLIENT_REGISTRATION);

		RedirectStrategy redirectStrategy = mock(RedirectStrategy.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2Login((oauth2Login) ->
					oauth2Login
						.clientRegistrationRepository(this.clientRegistrationRepository)
						.authorizationEndpoint((authorizationEndpoint) ->
							authorizationEndpoint
								.authorizationRedirectStrategy(this.redirectStrategy)
						)
				);
			// @formatter:on
			return super.configureFilterChain(http);
		}

	}

	@EnableWebSecurity
	static class OAuth2LoginConfigCustomAuthorizationRedirectStrategyInLambda
			extends CommonLambdaSecurityFilterChainConfig {

		private final ClientRegistrationRepository clientRegistrationRepository = new InMemoryClientRegistrationRepository(
				GOOGLE_CLIENT_REGISTRATION);

		RedirectStrategy redirectStrategy = mock(RedirectStrategy.class);

		@Bean
		SecurityFilterChain configureFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.oauth2Login((oauth2Login) ->
							oauth2Login
									.clientRegistrationRepository(this.clientRegistrationRepository)
									.authorizationEndpoint((authorizationEndpoint) ->
											authorizationEndpoint
													.authorizationRedirectStrategy(this.redirectStrategy)
									)
					);
			// @formatter:on
			return super.configureFilterChain(http);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginConfigMultipleClients extends CommonSecurityFilterChainConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.oauth2Login()
					.clientRegistrationRepository(
							new InMemoryClientRegistrationRepository(
									GOOGLE_CLIENT_REGISTRATION, GITHUB_CLIENT_REGISTRATION));
			// @formatter:on
			return super.configureFilterChain(http);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginConfigAuthorizationCodeClientAndOtherClients extends CommonSecurityFilterChainConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.oauth2Login()
					.clientRegistrationRepository(
							new InMemoryClientRegistrationRepository(
									GOOGLE_CLIENT_REGISTRATION, CLIENT_CREDENTIALS_REGISTRATION));
			// @formatter:on
			return super.configureFilterChain(http);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginConfigCustomLoginPage extends CommonSecurityFilterChainConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.oauth2Login()
					.clientRegistrationRepository(
							new InMemoryClientRegistrationRepository(GOOGLE_CLIENT_REGISTRATION))
					.loginPage("/custom-login");
			// @formatter:on
			return super.configureFilterChain(http);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginConfigCustomLoginPageInLambda extends CommonLambdaSecurityFilterChainConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2Login((oauth2Login) ->
						oauth2Login
							.clientRegistrationRepository(
									new InMemoryClientRegistrationRepository(GOOGLE_CLIENT_REGISTRATION))
							.loginPage("/custom-login")
				);
			// @formatter:on
			return super.configureFilterChain(http);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginConfigWithOidcLogoutSuccessHandler extends CommonSecurityFilterChainConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.logout()
					.logoutSuccessHandler(oidcLogoutSuccessHandler());
			// @formatter:on
			return super.configureFilterChain(http);
		}

		@Bean
		OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler() {
			return new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository());
		}

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			Map<String, Object> providerMetadata = Collections.singletonMap("end_session_endpoint", "https://logout");
			return new InMemoryClientRegistrationRepository(TestClientRegistrations.clientRegistration()
				.providerConfigurationMetadata(providerMetadata)
				.build());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginWithHttpBasicConfig extends CommonSecurityFilterChainConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2Login()
					.clientRegistrationRepository(
							new InMemoryClientRegistrationRepository(GOOGLE_CLIENT_REGISTRATION))
					.and()
				.httpBasic();
			// @formatter:on
			return super.configureFilterChain(http);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginWithOidcSessionRegistry {

		private final OidcSessionRegistry registry = mock(OidcSessionRegistry.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2Login((oauth2) -> oauth2
					.clientRegistrationRepository(
							new InMemoryClientRegistrationRepository(GOOGLE_CLIENT_REGISTRATION))
					.oidcSessionRegistry(this.registry)
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		OidcSessionRegistry oidcSessionRegistry() {
			return this.registry;
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OAuth2LoginWithXHREntryPointConfig extends CommonSecurityFilterChainConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.oauth2Login()
					.clientRegistrationRepository(
							new InMemoryClientRegistrationRepository(GOOGLE_CLIENT_REGISTRATION))
					.and()
				.exceptionHandling()
					.defaultAuthenticationEntryPointFor(
							new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
							new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"));
			// @formatter:on
			return super.configureFilterChain(http);
		}

	}

	private abstract static class CommonSecurityFilterChainConfig {

		SecurityFilterChain configureFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.securityContext()
					.securityContextRepository(securityContextRepository())
					.and()
				.oauth2Login()
					.tokenEndpoint()
						.accessTokenResponseClient(createOauth2AccessTokenResponseClient())
						.and()
					.userInfoEndpoint()
						.userService(createOauth2UserService())
						.oidcUserService(createOidcUserService());
			// @formatter:on
			return http.build();
		}

		@Bean
		SecurityContextRepository securityContextRepository() {
			return new HttpSessionSecurityContextRepository();
		}

		@Bean
		HttpSessionOAuth2AuthorizationRequestRepository oauth2AuthorizationRequestRepository() {
			return new HttpSessionOAuth2AuthorizationRequestRepository();
		}

	}

	private abstract static class CommonLambdaSecurityFilterChainConfig {

		SecurityFilterChain configureFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.securityContext((securityContext) ->
					securityContext
						.securityContextRepository(securityContextRepository())
				)
				.oauth2Login((oauth2Login) ->
					oauth2Login
						.tokenEndpoint((tokenEndpoint) ->
							tokenEndpoint
								.accessTokenResponseClient(createOauth2AccessTokenResponseClient())
						)
						.userInfoEndpoint((userInfoEndpoint) ->
							userInfoEndpoint
								.userService(createOauth2UserService())
								.oidcUserService(createOidcUserService())
						)
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		SecurityContextRepository securityContextRepository() {
			return new HttpSessionSecurityContextRepository();
		}

		@Bean
		HttpSessionOAuth2AuthorizationRequestRepository oauth2AuthorizationRequestRepository() {
			return new HttpSessionOAuth2AuthorizationRequestRepository();
		}

	}

	@Configuration
	static class JwtDecoderFactoryConfig {

		@Bean
		JwtDecoderFactory<ClientRegistration> jwtDecoderFactory() {
			return (clientRegistration) -> getJwtDecoder();
		}

		private static JwtDecoder getJwtDecoder() {
			Map<String, Object> claims = new HashMap<>();
			claims.put(IdTokenClaimNames.SUB, "sub123");
			claims.put(IdTokenClaimNames.ISS, "http://localhost/iss");
			claims.put(IdTokenClaimNames.AUD, Arrays.asList("clientId", "a", "u", "d"));
			claims.put(IdTokenClaimNames.AZP, "clientId");
			Jwt jwt = TestJwts.jwt().claims((c) -> c.putAll(claims)).build();
			JwtDecoder jwtDecoder = mock(JwtDecoder.class);
			given(jwtDecoder.decode(any())).willReturn(jwt);
			return jwtDecoder;
		}

	}

	@Configuration
	static class NoUniqueJwtDecoderFactoryConfig {

		@Bean
		JwtDecoderFactory<ClientRegistration> jwtDecoderFactory1() {
			return (clientRegistration) -> JwtDecoderFactoryConfig.getJwtDecoder();
		}

		@Bean
		JwtDecoderFactory<ClientRegistration> jwtDecoderFactory2() {
			return (clientRegistration) -> JwtDecoderFactoryConfig.getJwtDecoder();
		}

	}

}
