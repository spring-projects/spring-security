/*
 * Copyright 2002-2017 the original author or authors.
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.http.HttpHeaders;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;
import org.springframework.security.web.server.authentication.ServerX509AuthenticationConverter;
import reactor.core.publisher.Mono;
import reactor.test.publisher.TestPublisher;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.ServerHttpSecurityConfigurationBuilder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.LogoutWebFilter;
import org.springframework.security.web.server.authentication.logout.SecurityContextServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CsrfServerLogoutHandler;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.security.web.server.authentication.AnonymousAuthenticationWebFilterTests;
import org.springframework.security.web.server.authentication.HttpBasicServerAuthenticationEntryPoint;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class ServerHttpSecurityTests {
	@Mock
	private ServerSecurityContextRepository contextRepository;
	@Mock
	private ReactiveAuthenticationManager authenticationManager;
	@Mock
	private ServerCsrfTokenRepository csrfTokenRepository;

	private ServerHttpSecurity http;

	@Before
	public void setup() {
		this.http = ServerHttpSecurityConfigurationBuilder.http()
			.authenticationManager(this.authenticationManager);
	}

	@Test
	public void defaults() {
		TestPublisher<SecurityContext> securityContext = TestPublisher.create();
		when(this.contextRepository.load(any())).thenReturn(securityContext.mono());
		this.http.securityContextRepository(this.contextRepository);

		WebTestClient client = buildClient();

		FluxExchangeResult<String> result = client.get()
			.uri("/")
			.exchange()
			.expectHeader().valueMatches(HttpHeaders.CACHE_CONTROL, ".+")
			.returnResult(String.class);

		assertThat(result.getResponseCookies()).isEmpty();
		// there is no need to try and load the SecurityContext by default
		securityContext.assertWasNotSubscribed();
	}

	@Test
	public void basic() {
		given(this.authenticationManager.authenticate(any())).willReturn(Mono.just(new TestingAuthenticationToken("rob", "rob", "ROLE_USER", "ROLE_ADMIN")));

		this.http.securityContextRepository(new WebSessionServerSecurityContextRepository());
		this.http.httpBasic();
		this.http.authenticationManager(this.authenticationManager);
		ServerHttpSecurity.AuthorizeExchangeSpec authorize = this.http.authorizeExchange();
		authorize.anyExchange().authenticated();

		WebTestClient client = buildClient();

		EntityExchangeResult<String> result = client.get()
			.uri("/")
			.headers(headers -> headers.setBasicAuth("rob", "rob"))
			.exchange()
			.expectStatus().isOk()
			.expectHeader().valueMatches(HttpHeaders.CACHE_CONTROL, ".+")
			.expectBody(String.class).consumeWith(b -> assertThat(b.getResponseBody()).isEqualTo("ok"))
			.returnResult();

		assertThat(result.getResponseCookies().getFirst("SESSION")).isNull();
	}

	@Test
	public void basicWhenNoCredentialsThenUnauthorized() {
		this.http.authorizeExchange().anyExchange().authenticated();

		WebTestClient client = buildClient();
		client
			.get()
			.uri("/")
			.exchange()
			.expectStatus().isUnauthorized()
			.expectHeader().valueMatches(HttpHeaders.CACHE_CONTROL, ".+")
			.expectBody().isEmpty();
	}

	@Test
	public void buildWhenServerWebExchangeFromContextThenFound() {
		SecurityWebFilterChain filter = this.http.build();

		WebTestClient client = WebTestClient.bindToController(new SubscriberContextController())
				.webFilter(new WebFilterChainProxy(filter))
				.build();

		client.get().uri("/foo/bar")
				.exchange()
				.expectBody(String.class).isEqualTo("/foo/bar");
	}

	@Test
	public void csrfServerLogoutHandlerNotAppliedIfCsrfIsntEnabled() {
		SecurityWebFilterChain securityWebFilterChain = this.http.csrf().disable().build();

		assertThat(getWebFilter(securityWebFilterChain, CsrfWebFilter.class))
				.isNotPresent();

		Optional<ServerLogoutHandler> logoutHandler = getWebFilter(securityWebFilterChain, LogoutWebFilter.class)
				.map(logoutWebFilter -> (ServerLogoutHandler) ReflectionTestUtils.getField(logoutWebFilter, LogoutWebFilter.class, "logoutHandler"));

		assertThat(logoutHandler)
				.get()
				.isExactlyInstanceOf(SecurityContextServerLogoutHandler.class);
	}

	@Test
	public void csrfServerLogoutHandlerAppliedIfCsrfIsEnabled() {
		SecurityWebFilterChain securityWebFilterChain = this.http.csrf().csrfTokenRepository(this.csrfTokenRepository).and().build();

		assertThat(getWebFilter(securityWebFilterChain, CsrfWebFilter.class))
				.get()
				.extracting(csrfWebFilter -> ReflectionTestUtils.getField(csrfWebFilter, "csrfTokenRepository"))
				.isEqualTo(this.csrfTokenRepository);

		Optional<ServerLogoutHandler> logoutHandler = getWebFilter(securityWebFilterChain, LogoutWebFilter.class)
				.map(logoutWebFilter -> (ServerLogoutHandler) ReflectionTestUtils.getField(logoutWebFilter, LogoutWebFilter.class, "logoutHandler"));

		assertThat(logoutHandler)
				.get()
				.isExactlyInstanceOf(DelegatingServerLogoutHandler.class)
				.extracting(delegatingLogoutHandler ->
						((List<ServerLogoutHandler>) ReflectionTestUtils.getField(delegatingLogoutHandler, DelegatingServerLogoutHandler.class, "delegates")).stream()
								.map(ServerLogoutHandler::getClass)
								.collect(Collectors.toList()))
				.isEqualTo(Arrays.asList(SecurityContextServerLogoutHandler.class, CsrfServerLogoutHandler.class));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void addFilterAfterIsApplied(){
		SecurityWebFilterChain securityWebFilterChain =  this.http.addFilterAfter(new TestWebFilter(), SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE).build();
		List filters = securityWebFilterChain.getWebFilters().map(WebFilter::getClass).collectList().block();

		assertThat(filters).isNotNull()
				.isNotEmpty()
				.containsSequence(SecurityContextServerWebExchangeWebFilter.class, TestWebFilter.class);

	}

	@Test
	@SuppressWarnings("unchecked")
	public void addFilterBeforeIsApplied(){
		SecurityWebFilterChain securityWebFilterChain =  this.http.addFilterBefore(new TestWebFilter(), SecurityWebFiltersOrder.SECURITY_CONTEXT_SERVER_WEB_EXCHANGE).build();
		List filters = securityWebFilterChain.getWebFilters().map(WebFilter::getClass).collectList().block();

		assertThat(filters).isNotNull()
				.isNotEmpty()
				.containsSequence(TestWebFilter.class, SecurityContextServerWebExchangeWebFilter.class);

	}

	@Test
	public void anonymous(){
		SecurityWebFilterChain securityFilterChain = this.http.anonymous().and().build();
		WebTestClient client = WebTestClientBuilder.bindToControllerAndWebFilters(AnonymousAuthenticationWebFilterTests.HttpMeController.class,
				securityFilterChain).build();

		client.get()
				.uri("/me")
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class).isEqualTo("anonymousUser");

	}

	@Test
	public void basicWithAnonymous() {
		given(this.authenticationManager.authenticate(any())).willReturn(Mono.just(new TestingAuthenticationToken("rob", "rob", "ROLE_USER", "ROLE_ADMIN")));

		this.http.securityContextRepository(new WebSessionServerSecurityContextRepository());
		this.http.httpBasic().and().anonymous();
		this.http.authenticationManager(this.authenticationManager);
		ServerHttpSecurity.AuthorizeExchangeSpec authorize = this.http.authorizeExchange();
		authorize.anyExchange().hasAuthority("ROLE_ADMIN");

		WebTestClient client = buildClient();

		EntityExchangeResult<String> result = client.get()
				.uri("/")
				.headers(headers -> headers.setBasicAuth("rob", "rob"))
				.exchange()
				.expectStatus().isOk()
				.expectHeader().valueMatches(HttpHeaders.CACHE_CONTROL, ".+")
				.expectBody(String.class).consumeWith(b -> assertThat(b.getResponseBody()).isEqualTo("ok"))
				.returnResult();

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

		EntityExchangeResult<String> result = client.get()
				.uri("/")
				.exchange()
				.expectStatus().isUnauthorized()
				.expectHeader().value(HttpHeaders.WWW_AUTHENTICATE, value -> assertThat(value).contains("myrealm"))
				.expectBody(String.class)
				.returnResult();

		assertThat(result.getResponseCookies().getFirst("SESSION")).isNull();
	}

	@Test
	@SuppressWarnings("unchecked")
	public void addsX509FilterWhenX509AuthenticationIsConfigured() {
		X509PrincipalExtractor mockExtractor = mock(X509PrincipalExtractor.class);
		ReactiveAuthenticationManager mockAuthenticationManager = mock(ReactiveAuthenticationManager.class);

		this.http.x509()
				.principalExtractor(mockExtractor)
				.authenticationManager(mockAuthenticationManager)
				.and();

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

	private boolean isX509Filter(WebFilter filter) {
		try {
			Object converter = ReflectionTestUtils.getField(filter, "authenticationConverter");
			return converter.getClass().isAssignableFrom(ServerX509AuthenticationConverter.class);
		} catch (IllegalArgumentException e) {
			// field doesn't exist
			return false;
		}
	}

	private <T extends WebFilter> Optional<T> getWebFilter(SecurityWebFilterChain filterChain, Class<T> filterClass) {
		return (Optional<T>) filterChain.getWebFilters()
				.filter(Objects::nonNull)
				.filter(filter -> filter.getClass().isAssignableFrom(filterClass))
				.singleOrEmpty()
				.blockOptional();
	}

	private WebTestClient buildClient() {
		WebFilterChainProxy springSecurityFilterChain = new WebFilterChainProxy(
			this.http.build());
		return WebTestClientBuilder.bindToWebFilters(springSecurityFilterChain).build();
	}

	@RestController
	private static class SubscriberContextController {
		@GetMapping("/**")
		Mono<String> pathWithinApplicationFromContext() {
			return Mono.subscriberContext()
				.filter(c -> c.hasKey(ServerWebExchange.class))
				.map(c -> c.get(ServerWebExchange.class))
				.map(e -> e.getRequest().getPath().pathWithinApplication().value());
		}
	}

	private static class TestWebFilter implements WebFilter {
		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			return chain.filter(exchange);
		}
	}
}
