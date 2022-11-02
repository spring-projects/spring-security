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

package org.springframework.security.config.web.server;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.publisher.TestPublisher;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.ServerHttpSecurityConfigurationBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.server.OAuth2AuthorizationRequestRedirectWebFilter;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.server.authentication.OAuth2LoginAuthenticationWebFilter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.web.server.authentication.AnonymousAuthenticationWebFilterTests;
import org.springframework.security.web.server.authentication.HttpBasicServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerX509AuthenticationConverter;
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.LogoutWebFilter;
import org.springframework.security.web.server.authentication.logout.SecurityContextServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CsrfServerLogoutHandler;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.security.web.server.csrf.DefaultCsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestHandler;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author Rob Winch
 * @author Eddú Meléndez
 * @since 5.0
 */
@ExtendWith(MockitoExtension.class)
public class ServerHttpSecurityTests {

	@Mock
	private ServerSecurityContextRepository contextRepository;

	@Mock
	private ReactiveAuthenticationManager authenticationManager;

	@Mock
	private ServerCsrfTokenRepository csrfTokenRepository;

	private ServerHttpSecurity http;

	@BeforeEach
	public void setup() {
		this.http = ServerHttpSecurityConfigurationBuilder.http().authenticationManager(this.authenticationManager);
	}

	@Test
	public void defaults() {
		TestPublisher<SecurityContext> securityContext = TestPublisher.create();
		given(this.contextRepository.load(any())).willReturn(securityContext.mono());
		this.http.securityContextRepository(this.contextRepository);
		WebTestClient client = buildClient();
		// @formatter:off
		FluxExchangeResult<String> result = client.get()
				.uri("/")
				.exchange()
				.expectHeader().valueMatches(HttpHeaders.CACHE_CONTROL, ".+")
				.returnResult(String.class);
		// @formatter:on
		assertThat(result.getResponseCookies()).isEmpty();
		// there is no need to try and load the SecurityContext by default
		securityContext.assertWasNotSubscribed();
	}

	@Test
	public void basic() {
		given(this.authenticationManager.authenticate(any()))
				.willReturn(Mono.just(new TestingAuthenticationToken("rob", "rob", "ROLE_USER", "ROLE_ADMIN")));
		this.http.httpBasic();
		this.http.authenticationManager(this.authenticationManager);
		ServerHttpSecurity.AuthorizeExchangeSpec authorize = this.http.authorizeExchange();
		authorize.anyExchange().authenticated();
		WebTestClient client = buildClient();
		// @formatter:off
		EntityExchangeResult<String> result = client.get()
				.uri("/")
				.headers((headers) -> headers
						.setBasicAuth("rob", "rob")
				)
				.exchange()
				.expectStatus().isOk()
				.expectHeader().valueMatches(HttpHeaders.CACHE_CONTROL, ".+")
				.expectBody(String.class).consumeWith((b) -> assertThat(b.getResponseBody()).isEqualTo("ok"))
				.returnResult();
		// @formatter:on
		assertThat(result.getResponseCookies().getFirst("SESSION")).isNull();
	}

	@Test
	public void basicWithGlobalWebSessionServerSecurityContextRepository() {
		given(this.authenticationManager.authenticate(any()))
				.willReturn(Mono.just(new TestingAuthenticationToken("rob", "rob", "ROLE_USER", "ROLE_ADMIN")));
		this.http.securityContextRepository(new WebSessionServerSecurityContextRepository());
		this.http.httpBasic();
		this.http.authenticationManager(this.authenticationManager);
		ServerHttpSecurity.AuthorizeExchangeSpec authorize = this.http.authorizeExchange();
		authorize.anyExchange().authenticated();
		WebTestClient client = buildClient();
		// @formatter:off
		EntityExchangeResult<String> result = client.get()
				.uri("/")
				.headers((headers) -> headers
						.setBasicAuth("rob", "rob")
				)
				.exchange()
				.expectStatus().isOk()
				.expectHeader().valueMatches(HttpHeaders.CACHE_CONTROL, ".+")
				.expectBody(String.class).consumeWith((b) -> assertThat(b.getResponseBody()).isEqualTo("ok"))
				.returnResult();
		// @formatter:on
		assertThat(result.getResponseCookies().getFirst("SESSION")).isNotNull();
	}

	@Test
	public void basicWhenNoCredentialsThenUnauthorized() {
		this.http.authorizeExchange().anyExchange().authenticated();
		WebTestClient client = buildClient();
		// @formatter:off
		client.get().uri("/")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().valueMatches(HttpHeaders.CACHE_CONTROL, ".+")
				.expectBody().isEmpty();
		// @formatter:on
	}

	@Test
	public void basicWhenXHRRequestThenUnauthorized() {
		ServerAuthenticationEntryPoint authenticationEntryPoint = spy(
				new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED));
		this.http.httpBasic().authenticationEntryPoint(authenticationEntryPoint);
		this.http.authorizeExchange().anyExchange().authenticated();
		WebTestClient client = buildClient();
		// @formatter:off
		client.get().uri("/")
				.header("X-Requested-With", "XMLHttpRequest")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().doesNotExist("WWW-Authenticate")
				.expectHeader().valueMatches(HttpHeaders.CACHE_CONTROL, ".+")
				.expectBody().isEmpty();
		// @formatter:on
		verify(authenticationEntryPoint).commence(any(), any());
	}

	@Test
	public void basicWhenCustomAuthenticationFailureHandlerThenUses() {
		ReactiveAuthenticationManager authenticationManager = mock(ReactiveAuthenticationManager.class);
		ServerAuthenticationFailureHandler authenticationFailureHandler = mock(
				ServerAuthenticationFailureHandler.class);
		this.http.httpBasic().authenticationFailureHandler(authenticationFailureHandler);
		this.http.httpBasic().authenticationManager(authenticationManager);
		this.http.authorizeExchange().anyExchange().authenticated();
		given(authenticationManager.authenticate(any()))
				.willReturn(Mono.error(() -> new BadCredentialsException("bad")));
		given(authenticationFailureHandler.onAuthenticationFailure(any(), any())).willReturn(Mono.empty());
		WebTestClient client = buildClient();
		// @formatter:off
		client.get().uri("/")
			.headers((headers) -> headers.setBasicAuth("user", "password"))
			.exchange()
			.expectStatus().isOk();
		// @formatter:on
		verify(authenticationFailureHandler).onAuthenticationFailure(any(), any());
	}

	@Test
	public void buildWhenServerWebExchangeFromContextThenFound() {
		SecurityWebFilterChain filter = this.http.build();
		// @formatter:off
		WebTestClient client = WebTestClient
				.bindToController(new SubscriberContextController())
				.webFilter(new WebFilterChainProxy(filter))
				.build();
		client.get()
				.uri("/foo/bar")
				.exchange()
				.expectBody(String.class).isEqualTo("/foo/bar");
		// @formatter:on
	}

	@Test
	public void csrfServerLogoutHandlerNotAppliedIfCsrfIsntEnabled() {
		SecurityWebFilterChain securityWebFilterChain = this.http.csrf().disable().build();
		assertThat(getWebFilter(securityWebFilterChain, CsrfWebFilter.class)).isNotPresent();
		Optional<ServerLogoutHandler> logoutHandler = getWebFilter(securityWebFilterChain, LogoutWebFilter.class)
				.map((logoutWebFilter) -> (ServerLogoutHandler) ReflectionTestUtils.getField(logoutWebFilter,
						LogoutWebFilter.class, "logoutHandler"));
		assertThat(logoutHandler).get().isExactlyInstanceOf(SecurityContextServerLogoutHandler.class);
	}

	@Test
	public void csrfServerLogoutHandlerAppliedIfCsrfIsEnabled() {
		SecurityWebFilterChain securityWebFilterChain = this.http.csrf().csrfTokenRepository(this.csrfTokenRepository)
				.and().build();
		assertThat(getWebFilter(securityWebFilterChain, CsrfWebFilter.class)).get()
				.extracting((csrfWebFilter) -> ReflectionTestUtils.getField(csrfWebFilter, "csrfTokenRepository"))
				.isEqualTo(this.csrfTokenRepository);
		Optional<ServerLogoutHandler> logoutHandler = getWebFilter(securityWebFilterChain, LogoutWebFilter.class)
				.map((logoutWebFilter) -> (ServerLogoutHandler) ReflectionTestUtils.getField(logoutWebFilter,
						LogoutWebFilter.class, "logoutHandler"));
		assertThat(logoutHandler).get().isExactlyInstanceOf(DelegatingServerLogoutHandler.class)
				.extracting((delegatingLogoutHandler) -> ((List<ServerLogoutHandler>) ReflectionTestUtils
						.getField(delegatingLogoutHandler, DelegatingServerLogoutHandler.class, "delegates")).stream()
								.map(ServerLogoutHandler::getClass).collect(Collectors.toList()))
				.isEqualTo(Arrays.asList(SecurityContextServerLogoutHandler.class, CsrfServerLogoutHandler.class));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void addFilterAfterIsApplied() {
		SecurityWebFilterChain securityWebFilterChain = this.http
				.addFilterAfter(new TestWebFilter(), SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE)
				.build();
		// @formatter:off
		List filters = securityWebFilterChain.getWebFilters()
				.map(WebFilter::getClass)
				.collectList()
				.block();
		// @formatter:on
		assertThat(filters).isNotNull().isNotEmpty().containsSequence(SecurityContextServerWebExchangeWebFilter.class,
				TestWebFilter.class);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void addFilterBeforeIsApplied() {
		SecurityWebFilterChain securityWebFilterChain = this.http
				.addFilterBefore(new TestWebFilter(), SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE)
				.build();
		// @formatter:off
		List filters = securityWebFilterChain.getWebFilters()
				.map(WebFilter::getClass)
				.collectList()
				.block();
		// @formatter:on
		assertThat(filters).isNotNull().isNotEmpty().containsSequence(TestWebFilter.class,
				SecurityContextServerWebExchangeWebFilter.class);
	}

	@Test
	public void anonymous() {
		// @formatter:off
		SecurityWebFilterChain securityFilterChain = this.http
				.anonymous().and()
				.build();
		WebTestClient client = WebTestClientBuilder
				.bindToControllerAndWebFilters(AnonymousAuthenticationWebFilterTests.HttpMeController.class, securityFilterChain)
				.build();
		client.get()
				.uri("/me")
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("anonymousUser");
		// @formatter:on
	}

	@Test
	public void getWhenAnonymousConfiguredThenAuthenticationIsAnonymous() {
		SecurityWebFilterChain securityFilterChain = this.http.anonymous(withDefaults()).build();
		// @formatter:off
		WebTestClient client = WebTestClientBuilder
				.bindToControllerAndWebFilters(AnonymousAuthenticationWebFilterTests.HttpMeController.class, securityFilterChain)
				.build();
		client.get()
				.uri("/me")
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("anonymousUser");
		// @formatter:on
	}

	@Test
	public void basicWithAnonymous() {
		given(this.authenticationManager.authenticate(any()))
				.willReturn(Mono.just(new TestingAuthenticationToken("rob", "rob", "ROLE_USER", "ROLE_ADMIN")));
		this.http.httpBasic().and().anonymous();
		this.http.authenticationManager(this.authenticationManager);
		ServerHttpSecurity.AuthorizeExchangeSpec authorize = this.http.authorizeExchange();
		authorize.anyExchange().hasAuthority("ROLE_ADMIN");
		WebTestClient client = buildClient();
		// @formatter:off
		EntityExchangeResult<String> result = client.get()
				.uri("/")
				.headers((headers) -> headers
						.setBasicAuth("rob", "rob")
				).exchange()
				.expectStatus().isOk()
				.expectHeader().valueMatches(HttpHeaders.CACHE_CONTROL, ".+")
				.expectBody(String.class).consumeWith((b) -> assertThat(b.getResponseBody()).isEqualTo("ok"))
				.returnResult();
		// @formatter:on
		assertThat(result.getResponseCookies().getFirst("SESSION")).isNull();
	}

	@Test
	public void basicWithCustomRealmName() {
		this.http.securityContextRepository(new WebSessionServerSecurityContextRepository());
		HttpBasicServerAuthenticationEntryPoint authenticationEntryPoint = new HttpBasicServerAuthenticationEntryPoint();
		authenticationEntryPoint.setRealm("myrealm");
		this.http.httpBasic().authenticationEntryPoint(authenticationEntryPoint);
		this.http.authenticationManager(this.authenticationManager);
		ServerHttpSecurity.AuthorizeExchangeSpec authorize = this.http.authorizeExchange();
		authorize.anyExchange().authenticated();
		WebTestClient client = buildClient();
		// @formatter:off
		EntityExchangeResult<String> result = client.get()
				.uri("/")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, (value) -> assertThat(value).contains("myrealm"))
				.expectBody(String.class)
				.returnResult();
		// @formatter:on
		assertThat(result.getResponseCookies().getFirst("SESSION")).isNull();
	}

	@Test
	public void requestWhenBasicWithRealmNameInLambdaThenRealmNameUsed() {
		this.http.securityContextRepository(new WebSessionServerSecurityContextRepository());
		HttpBasicServerAuthenticationEntryPoint authenticationEntryPoint = new HttpBasicServerAuthenticationEntryPoint();
		authenticationEntryPoint.setRealm("myrealm");
		this.http.httpBasic((httpBasic) -> httpBasic.authenticationEntryPoint(authenticationEntryPoint));
		this.http.authenticationManager(this.authenticationManager);
		ServerHttpSecurity.AuthorizeExchangeSpec authorize = this.http.authorizeExchange();
		authorize.anyExchange().authenticated();
		WebTestClient client = buildClient();
		// @formatter:off
		EntityExchangeResult<String> result = client.get()
				.uri("/")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, (value) -> assertThat(value).contains("myrealm"))
				.expectBody(String.class)
				.returnResult();
		// @formatter:on
		assertThat(result.getResponseCookies().getFirst("SESSION")).isNull();
	}

	@Test
	public void basicWithCustomAuthenticationManager() {
		ReactiveAuthenticationManager customAuthenticationManager = mock(ReactiveAuthenticationManager.class);
		given(customAuthenticationManager.authenticate(any()))
				.willReturn(Mono.just(new TestingAuthenticationToken("rob", "rob", "ROLE_USER", "ROLE_ADMIN")));
		// @formatter:off
		SecurityWebFilterChain securityFilterChain = this.http
				.httpBasic()
					.authenticationManager(customAuthenticationManager)
					.and()
				.build();
		// @formatter:on
		WebFilterChainProxy springSecurityFilterChain = new WebFilterChainProxy(securityFilterChain);
		// @formatter:off
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(springSecurityFilterChain)
				.build();
		client.get()
				.uri("/").headers((headers) -> headers
						.setBasicAuth("rob", "rob")
				)
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).consumeWith((b) -> assertThat(b.getResponseBody()).isEqualTo("ok"));
		// @formatter:on
		verifyNoMoreInteractions(this.authenticationManager);
	}

	@Test
	public void requestWhenBasicWithAuthenticationManagerInLambdaThenAuthenticationManagerUsed() {
		ReactiveAuthenticationManager customAuthenticationManager = mock(ReactiveAuthenticationManager.class);
		given(customAuthenticationManager.authenticate(any()))
				.willReturn(Mono.just(new TestingAuthenticationToken("rob", "rob", "ROLE_USER", "ROLE_ADMIN")));
		// @formatter:off
		SecurityWebFilterChain securityFilterChain = this.http
				.httpBasic((httpBasic) -> httpBasic
						.authenticationManager(customAuthenticationManager)
				)
				.build();
		// @formatter:on
		WebFilterChainProxy springSecurityFilterChain = new WebFilterChainProxy(securityFilterChain);
		// @formatter:off
		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(springSecurityFilterChain)
				.build();
		client.get()
				.uri("/")
				.headers((headers) -> headers
						.setBasicAuth("rob", "rob")
				)
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).consumeWith((b) -> assertThat(b.getResponseBody()).isEqualTo("ok"));
		// @formatter:on
		verifyNoMoreInteractions(this.authenticationManager);
		verify(customAuthenticationManager).authenticate(any(Authentication.class));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void addsX509FilterWhenX509AuthenticationIsConfigured() {
		X509PrincipalExtractor mockExtractor = mock(X509PrincipalExtractor.class);
		ReactiveAuthenticationManager mockAuthenticationManager = mock(ReactiveAuthenticationManager.class);
		this.http.x509().principalExtractor(mockExtractor).authenticationManager(mockAuthenticationManager).and();
		SecurityWebFilterChain securityWebFilterChain = this.http.build();
		WebFilter x509WebFilter = securityWebFilterChain.getWebFilters().filter(this::isX509Filter).blockFirst();
		assertThat(x509WebFilter).isNotNull();
	}

	@Test
	public void x509WhenCustomizedThenAddsX509Filter() {
		X509PrincipalExtractor mockExtractor = mock(X509PrincipalExtractor.class);
		ReactiveAuthenticationManager mockAuthenticationManager = mock(ReactiveAuthenticationManager.class);
		this.http.x509(
				(x509) -> x509.principalExtractor(mockExtractor).authenticationManager(mockAuthenticationManager));
		SecurityWebFilterChain securityWebFilterChain = this.http.build();
		WebFilter x509WebFilter = securityWebFilterChain.getWebFilters().filter(this::isX509Filter).blockFirst();
		assertThat(x509WebFilter).isNotNull();
	}

	@Test
	public void addsX509FilterWhenX509AuthenticationIsConfiguredWithDefaults() {
		this.http.x509();
		SecurityWebFilterChain securityWebFilterChain = this.http.build();
		WebFilter x509WebFilter = securityWebFilterChain.getWebFilters().filter(this::isX509Filter).blockFirst();
		assertThat(x509WebFilter).isNotNull();
	}

	@Test
	public void x509WhenDefaultsThenAddsX509Filter() {
		this.http.x509(withDefaults());
		SecurityWebFilterChain securityWebFilterChain = this.http.build();
		WebFilter x509WebFilter = securityWebFilterChain.getWebFilters().filter(this::isX509Filter).blockFirst();
		assertThat(x509WebFilter).isNotNull();
	}

	@Test
	public void postWhenCsrfDisabledThenPermitted() {
		SecurityWebFilterChain securityFilterChain = this.http.csrf((csrf) -> csrf.disable()).build();
		WebFilterChainProxy springSecurityFilterChain = new WebFilterChainProxy(securityFilterChain);
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(springSecurityFilterChain).build();
		client.post().uri("/").exchange().expectStatus().isOk();
	}

	@Test
	public void postWhenCustomCsrfTokenRepositoryThenUsed() {
		ServerCsrfTokenRepository customServerCsrfTokenRepository = mock(ServerCsrfTokenRepository.class);
		given(customServerCsrfTokenRepository.loadToken(any(ServerWebExchange.class))).willReturn(Mono.empty());
		SecurityWebFilterChain securityFilterChain = this.http
				.csrf((csrf) -> csrf.csrfTokenRepository(customServerCsrfTokenRepository)).build();
		WebFilterChainProxy springSecurityFilterChain = new WebFilterChainProxy(securityFilterChain);
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(springSecurityFilterChain).build();
		client.post().uri("/").exchange().expectStatus().isForbidden();
		verify(customServerCsrfTokenRepository).loadToken(any());
	}

	@Test
	public void postWhenCustomRequestHandlerThenUsed() {
		CsrfToken csrfToken = new DefaultCsrfToken("headerName", "paramName", "tokenValue");
		given(this.csrfTokenRepository.loadToken(any(ServerWebExchange.class))).willReturn(Mono.just(csrfToken));
		given(this.csrfTokenRepository.generateToken(any(ServerWebExchange.class))).willReturn(Mono.empty());
		ServerCsrfTokenRequestHandler requestHandler = mock(ServerCsrfTokenRequestHandler.class);
		given(requestHandler.resolveCsrfTokenValue(any(ServerWebExchange.class), any(CsrfToken.class)))
				.willReturn(Mono.just(csrfToken.getToken()));
		// @formatter:off
		this.http.csrf((csrf) -> csrf
			.csrfTokenRepository(this.csrfTokenRepository)
			.csrfTokenRequestHandler(requestHandler)
		);
		// @formatter:on
		WebTestClient client = buildClient();
		client.post().uri("/").exchange().expectStatus().isOk();
		verify(this.csrfTokenRepository, times(2)).loadToken(any(ServerWebExchange.class));
		verify(this.csrfTokenRepository).generateToken(any(ServerWebExchange.class));
		verify(requestHandler).handle(any(ServerWebExchange.class), any());
		verify(requestHandler).resolveCsrfTokenValue(any(ServerWebExchange.class), any());
	}

	@Test
	public void postWhenServerXorCsrfTokenRequestAttributeHandlerThenOk() {
		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "token");
		given(this.csrfTokenRepository.loadToken(any(ServerWebExchange.class))).willReturn(Mono.just(csrfToken));
		given(this.csrfTokenRepository.generateToken(any(ServerWebExchange.class))).willReturn(Mono.empty());
		ServerCsrfTokenRequestHandler requestHandler = new XorServerCsrfTokenRequestAttributeHandler();
		// @formatter:off
		this.http.csrf((csrf) -> csrf
			.csrfTokenRepository(this.csrfTokenRepository)
			.csrfTokenRequestHandler(requestHandler)
		);
		// @formatter:on

		// Generate masked CSRF token value
		ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		requestHandler.handle(exchange, Mono.just(csrfToken));
		Mono<CsrfToken> csrfTokenAttribute = exchange.getAttribute(CsrfToken.class.getName());
		String actualTokenValue = csrfTokenAttribute.map(CsrfToken::getToken).block();
		assertThat(actualTokenValue).isNotEqualTo(csrfToken.getToken());

		WebTestClient client = buildClient();
		// @formatter:off
		client.post()
				.uri("/")
				.header(csrfToken.getHeaderName(), actualTokenValue)
				.exchange()
				.expectStatus().isOk();
		// @formatter:on
		verify(this.csrfTokenRepository, times(2)).loadToken(any(ServerWebExchange.class));
		verify(this.csrfTokenRepository).generateToken(any(ServerWebExchange.class));
	}

	@Test
	public void shouldConfigureRequestCacheForOAuth2LoginAuthenticationEntryPointAndSuccessHandler() {
		ServerRequestCache requestCache = spy(new WebSessionServerRequestCache());
		ReactiveClientRegistrationRepository clientRegistrationRepository = mock(
				ReactiveClientRegistrationRepository.class);
		SecurityWebFilterChain securityFilterChain = this.http.oauth2Login()
				.clientRegistrationRepository(clientRegistrationRepository).and().authorizeExchange().anyExchange()
				.authenticated().and().requestCache((c) -> c.requestCache(requestCache)).build();
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(securityFilterChain).build();
		client.get().uri("/test").exchange();
		ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
		verify(requestCache).saveRequest(captor.capture());
		assertThat(captor.getValue().getRequest().getURI().toString()).isEqualTo("/test");
		OAuth2LoginAuthenticationWebFilter authenticationWebFilter = getWebFilter(securityFilterChain,
				OAuth2LoginAuthenticationWebFilter.class).get();
		Object handler = ReflectionTestUtils.getField(authenticationWebFilter, "authenticationSuccessHandler");
		assertThat(ReflectionTestUtils.getField(handler, "requestCache")).isSameAs(requestCache);
	}

	@Test
	public void shouldConfigureAuthorizationRequestRepositoryForOAuth2Login() {
		ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = mock(
				ServerAuthorizationRequestRepository.class);
		ReactiveClientRegistrationRepository clientRegistrationRepository = mock(
				ReactiveClientRegistrationRepository.class);
		OAuth2AuthorizationRequest authorizationRequest = TestOAuth2AuthorizationRequests.request().build();
		given(authorizationRequestRepository.removeAuthorizationRequest(any()))
				.willReturn(Mono.just(authorizationRequest));
		SecurityWebFilterChain securityFilterChain = this.http.oauth2Login()
				.clientRegistrationRepository(clientRegistrationRepository)
				.authorizationRequestRepository(authorizationRequestRepository).and().build();
		WebTestClient client = WebTestClientBuilder.bindToWebFilters(securityFilterChain).build();
		client.get().uri("/login/oauth2/code/registration-id").exchange();
		verify(authorizationRequestRepository).removeAuthorizationRequest(any());
	}

	@Test
	public void shouldUseDefaultAuthorizationRedirectStrategyForOAuth2Login() {
		ReactiveClientRegistrationRepository clientRegistrationRepository = mock(
				ReactiveClientRegistrationRepository.class);
		given(clientRegistrationRepository.findByRegistrationId(anyString()))
				.willReturn(Mono.just(TestClientRegistrations.clientRegistration().build()));

		SecurityWebFilterChain securityFilterChain = this.http.oauth2Login()
				.clientRegistrationRepository(clientRegistrationRepository).and().build();

		WebTestClient client = WebTestClientBuilder.bindToWebFilters(securityFilterChain).build();
		client.get().uri("/oauth2/authorization/registration-id").exchange().expectStatus().is3xxRedirection();

		OAuth2AuthorizationRequestRedirectWebFilter filter = getWebFilter(securityFilterChain,
				OAuth2AuthorizationRequestRedirectWebFilter.class).get();
		assertThat(ReflectionTestUtils.getField(filter, "authorizationRedirectStrategy"))
				.isInstanceOf(DefaultServerRedirectStrategy.class);
	}

	@Test
	public void shouldConfigureAuthorizationRedirectStrategyForOAuth2Login() {
		ServerRedirectStrategy authorizationRedirectStrategy = mock(ServerRedirectStrategy.class);
		ReactiveClientRegistrationRepository clientRegistrationRepository = mock(
				ReactiveClientRegistrationRepository.class);
		given(clientRegistrationRepository.findByRegistrationId(anyString()))
				.willReturn(Mono.just(TestClientRegistrations.clientRegistration().build()));
		given(authorizationRedirectStrategy.sendRedirect(any(), any())).willReturn(Mono.empty());

		SecurityWebFilterChain securityFilterChain = this.http.oauth2Login()
				.clientRegistrationRepository(clientRegistrationRepository)
				.authorizationRedirectStrategy(authorizationRedirectStrategy).and().build();

		WebTestClient client = WebTestClientBuilder.bindToWebFilters(securityFilterChain).build();
		client.get().uri("/oauth2/authorization/registration-id").exchange();
		verify(authorizationRedirectStrategy).sendRedirect(any(), any());

		OAuth2AuthorizationRequestRedirectWebFilter filter = getWebFilter(securityFilterChain,
				OAuth2AuthorizationRequestRedirectWebFilter.class).get();
		assertThat(ReflectionTestUtils.getField(filter, "authorizationRedirectStrategy"))
				.isSameAs(authorizationRedirectStrategy);
	}

	@Test
	public void shouldUseDefaultAuthorizationRedirectStrategyForOAuth2Client() {
		ReactiveClientRegistrationRepository clientRegistrationRepository = mock(
				ReactiveClientRegistrationRepository.class);
		given(clientRegistrationRepository.findByRegistrationId(anyString()))
				.willReturn(Mono.just(TestClientRegistrations.clientRegistration().build()));

		SecurityWebFilterChain securityFilterChain = this.http.oauth2Client()
				.clientRegistrationRepository(clientRegistrationRepository).and().build();

		WebTestClient client = WebTestClientBuilder.bindToWebFilters(securityFilterChain).build();
		client.get().uri("/oauth2/authorization/registration-id").exchange().expectStatus().is3xxRedirection();

		OAuth2AuthorizationRequestRedirectWebFilter filter = getWebFilter(securityFilterChain,
				OAuth2AuthorizationRequestRedirectWebFilter.class).get();
		assertThat(ReflectionTestUtils.getField(filter, "authorizationRedirectStrategy"))
				.isInstanceOf(DefaultServerRedirectStrategy.class);
	}

	@Test
	public void shouldConfigureAuthorizationRedirectStrategyForOAuth2Client() {
		ServerRedirectStrategy authorizationRedirectStrategy = mock(ServerRedirectStrategy.class);
		ReactiveClientRegistrationRepository clientRegistrationRepository = mock(
				ReactiveClientRegistrationRepository.class);
		given(clientRegistrationRepository.findByRegistrationId(anyString()))
				.willReturn(Mono.just(TestClientRegistrations.clientRegistration().build()));
		given(authorizationRedirectStrategy.sendRedirect(any(), any())).willReturn(Mono.empty());

		SecurityWebFilterChain securityFilterChain = this.http.oauth2Client()
				.clientRegistrationRepository(clientRegistrationRepository)
				.authorizationRedirectStrategy(authorizationRedirectStrategy).and().build();

		WebTestClient client = WebTestClientBuilder.bindToWebFilters(securityFilterChain).build();
		client.get().uri("/oauth2/authorization/registration-id").exchange();
		verify(authorizationRedirectStrategy).sendRedirect(any(), any());

		OAuth2AuthorizationRequestRedirectWebFilter filter = getWebFilter(securityFilterChain,
				OAuth2AuthorizationRequestRedirectWebFilter.class).get();
		assertThat(ReflectionTestUtils.getField(filter, "authorizationRedirectStrategy"))
				.isSameAs(authorizationRedirectStrategy);
	}

	private boolean isX509Filter(WebFilter filter) {
		try {
			Object converter = ReflectionTestUtils.getField(filter, "authenticationConverter");
			return converter.getClass().isAssignableFrom(ServerX509AuthenticationConverter.class);
		}
		catch (IllegalArgumentException ex) {
			// field doesn't exist
			return false;
		}
	}

	private <T extends WebFilter> Optional<T> getWebFilter(SecurityWebFilterChain filterChain, Class<T> filterClass) {
		return (Optional<T>) filterChain.getWebFilters().filter(Objects::nonNull)
				.filter((filter) -> filter.getClass().isAssignableFrom(filterClass)).singleOrEmpty().blockOptional();
	}

	private WebTestClient buildClient() {
		WebFilterChainProxy springSecurityFilterChain = new WebFilterChainProxy(this.http.build());
		return WebTestClientBuilder.bindToWebFilters(springSecurityFilterChain).build();
	}

	@RestController
	private static class SubscriberContextController {

		@GetMapping("/**")
		Mono<String> pathWithinApplicationFromContext() {
			return Mono.deferContextual(Mono::just).filter((c) -> c.hasKey(ServerWebExchange.class))
					.map((c) -> c.get(ServerWebExchange.class))
					.map((e) -> e.getRequest().getPath().pathWithinApplication().value());
		}

	}

	private static class TestWebFilter implements WebFilter {

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			return chain.filter(exchange);
		}

	}

}
