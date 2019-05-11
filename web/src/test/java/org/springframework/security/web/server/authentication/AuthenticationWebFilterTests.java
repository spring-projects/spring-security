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

package org.springframework.security.web.server.authentication;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import reactor.core.publisher.Mono;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author Rob Winch
 * @author Rafiullah Hamedy
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthenticationWebFilterTests {
	@Mock
	private ServerAuthenticationSuccessHandler successHandler;
	@Mock
	private ServerAuthenticationConverter authenticationConverter;
	@Mock
	private ReactiveAuthenticationManager authenticationManager;
	@Mock
	private ServerAuthenticationFailureHandler failureHandler;
	@Mock
	private ServerSecurityContextRepository securityContextRepository;
	@Mock
	private ReactiveAuthenticationManagerResolver<ServerHttpRequest> authenticationManagerResolver;

	private AuthenticationWebFilter filter;

	@Before
	public void setup() {
		this.filter = new AuthenticationWebFilter(this.authenticationManager);
		this.filter.setAuthenticationSuccessHandler(this.successHandler);
		this.filter.setServerAuthenticationConverter(this.authenticationConverter);
		this.filter.setSecurityContextRepository(this.securityContextRepository);
		this.filter.setAuthenticationFailureHandler(this.failureHandler);
	}

	@Test
	public void filterWhenDefaultsAndNoAuthenticationThenContinues() {
		this.filter = new AuthenticationWebFilter(this.authenticationManager);

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.filter)
			.build();

		EntityExchangeResult<String> result = client.get()
			.uri("/")
			.exchange()
			.expectStatus().isOk()
			.expectBody(String.class).consumeWith(b -> assertThat(b.getResponseBody()).isEqualTo("ok"))
			.returnResult();

		verifyZeroInteractions(this.authenticationManager);
		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenAuthenticationManagerResolverDefaultsAndNoAuthenticationThenContinues() {
		this.filter = new AuthenticationWebFilter(this.authenticationManagerResolver);

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.filter)
			.build();

		EntityExchangeResult<String> result = client.get()
			.uri("/")
			.exchange()
			.expectStatus().isOk()
			.expectBody(String.class).consumeWith(b -> assertThat(b.getResponseBody()).isEqualTo("ok"))
			.returnResult();

		verifyZeroInteractions(this.authenticationManagerResolver);
		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenDefaultsAndAuthenticationSuccessThenContinues() {
		when(this.authenticationManager.authenticate(any())).thenReturn(Mono.just(new TestingAuthenticationToken("test", "this", "ROLE")));
		this.filter = new AuthenticationWebFilter(this.authenticationManager);

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.filter)
			.build();

		EntityExchangeResult<String> result = client
			.get()
			.uri("/")
			.headers(headers -> headers.setBasicAuth("test", "this"))
			.exchange()
			.expectStatus().isOk()
			.expectBody(String.class).consumeWith(b -> assertThat(b.getResponseBody()).isEqualTo("ok"))
			.returnResult();

		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenAuthenticationManagerResolverDefaultsAndAuthenticationSuccessThenContinues() {
		when(this.authenticationManager.authenticate(any())).thenReturn(Mono.just(new TestingAuthenticationToken("test", "this", "ROLE")));
		when(this.authenticationManagerResolver.resolve(any())).thenReturn(Mono.just(this.authenticationManager));

		this.filter = new AuthenticationWebFilter(this.authenticationManagerResolver);

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.filter)
			.build();

		EntityExchangeResult<String> result = client
			.get()
			.uri("/")
			.headers(headers -> headers.setBasicAuth("test", "this"))
			.exchange()
			.expectStatus().isOk()
			.expectBody(String.class).consumeWith(b -> assertThat(b.getResponseBody()).isEqualTo("ok"))
			.returnResult();

		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenDefaultsAndAuthenticationFailThenUnauthorized() {
		when(this.authenticationManager.authenticate(any())).thenReturn(Mono.error(new BadCredentialsException("failed")));
		this.filter = new AuthenticationWebFilter(this.authenticationManager);

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.filter)
			.build();

		EntityExchangeResult<Void> result = client
			.get()
			.uri("/")
			.headers(headers -> headers.setBasicAuth("test", "this"))
			.exchange()
			.expectStatus().isUnauthorized()
			.expectHeader().valueMatches("WWW-Authenticate", "Basic realm=\"Realm\"")
			.expectBody().isEmpty();

		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenAuthenticationManagerResolverDefaultsAndAuthenticationFailThenUnauthorized() {
		when(this.authenticationManager.authenticate(any())).thenReturn(Mono.error(new BadCredentialsException("failed")));
		when(this.authenticationManagerResolver.resolve(any())).thenReturn(Mono.just(this.authenticationManager));

		this.filter = new AuthenticationWebFilter(this.authenticationManagerResolver);

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.filter)
			.build();

		EntityExchangeResult<Void> result = client
			.get()
			.uri("/")
			.headers(headers -> headers.setBasicAuth("test", "this"))
			.exchange()
			.expectStatus().isUnauthorized()
			.expectHeader().valueMatches("WWW-Authenticate", "Basic realm=\"Realm\"")
			.expectBody().isEmpty();

		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenConvertEmptyThenOk() {
		when(this.authenticationConverter.convert(any())).thenReturn(Mono.empty());

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.filter)
			.build();

		client
			.get()
			.uri("/")
			.exchange()
			.expectStatus().isOk()
			.expectBody(String.class).consumeWith(b -> assertThat(b.getResponseBody()).isEqualTo("ok"))
			.returnResult();

		verify(this.securityContextRepository, never()).save(any(), any());
		verifyZeroInteractions(this.authenticationManager, this.successHandler,
			this.failureHandler);
	}

	@Test
	public void filterWhenConvertErrorThenServerError() {
		when(this.authenticationConverter.convert(any())).thenReturn(Mono.error(new RuntimeException("Unexpected")));

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.filter)
			.build();

		client
			.get()
			.uri("/")
			.exchange()
			.expectStatus().is5xxServerError()
			.expectBody().isEmpty();

		verify(this.securityContextRepository, never()).save(any(), any());
		verifyZeroInteractions(this.authenticationManager, this.successHandler,
			this.failureHandler);
	}

	@Test
	public void filterWhenConvertAndAuthenticationSuccessThenSuccess() {
		Mono<Authentication> authentication = Mono.just(new TestingAuthenticationToken("test", "this", "ROLE_USER"));
		when(this.authenticationConverter.convert(any())).thenReturn(authentication);
		when(this.authenticationManager.authenticate(any())).thenReturn(authentication);
		when(this.successHandler.onAuthenticationSuccess(any(), any())).thenReturn(Mono.empty());
		when(this.securityContextRepository.save(any(), any())).thenAnswer( a -> Mono.just(a.getArguments()[0]));

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.filter)
			.build();

		client
			.get()
			.uri("/")
			.exchange()
			.expectStatus().isOk()
			.expectBody().isEmpty();

		verify(this.successHandler).onAuthenticationSuccess(any(),
			eq(authentication.block()));
		verify(this.securityContextRepository).save(any(), any());
		verifyZeroInteractions(this.failureHandler);
	}

	@Test
	public void filterWhenConvertAndAuthenticationEmptyThenServerError() {
		Mono<Authentication> authentication = Mono.just(new TestingAuthenticationToken("test", "this", "ROLE_USER"));
		when(this.authenticationConverter.convert(any())).thenReturn(authentication);
		when(this.authenticationManager.authenticate(any())).thenReturn(Mono.empty());

		WebTestClient client = WebTestClientBuilder
				.bindToWebFilters(this.filter)
				.build();

		client
				.get()
				.uri("/")
				.exchange()
				.expectStatus().is5xxServerError()
				.expectBody().isEmpty();

		verify(this.securityContextRepository, never()).save(any(), any());
		verifyZeroInteractions(this.successHandler, this.failureHandler);
	}

	@Test
	public void filterWhenNotMatchAndConvertAndAuthenticationSuccessThenContinues() {
		this.filter.setRequiresAuthenticationMatcher(e -> ServerWebExchangeMatcher.MatchResult.notMatch());

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.filter)
			.build();

		EntityExchangeResult<String> result = client
			.get()
			.uri("/")
			.headers(headers -> headers.setBasicAuth("test", "this"))
			.exchange()
			.expectStatus().isOk()
			.expectBody(String.class).consumeWith(b -> assertThat(b.getResponseBody()).isEqualTo("ok"))
			.returnResult();

		assertThat(result.getResponseCookies()).isEmpty();
		verifyZeroInteractions(this.authenticationConverter, this.authenticationManager, this.successHandler);
	}

	@Test
	public void filterWhenConvertAndAuthenticationFailThenEntryPoint() {
		Mono<Authentication> authentication = Mono.just(new TestingAuthenticationToken("test", "this", "ROLE_USER"));
		when(this.authenticationConverter.convert(any())).thenReturn(authentication);
		when(this.authenticationManager.authenticate(any())).thenReturn(Mono.error(new BadCredentialsException("Failed")));
		when(this.failureHandler.onAuthenticationFailure(any(), any())).thenReturn(Mono.empty());

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.filter)
			.build();

		client
			.get()
			.uri("/")
			.exchange()
			.expectStatus().isOk()
			.expectBody().isEmpty();

		verify(this.failureHandler).onAuthenticationFailure(any(), any());
		verify(this.securityContextRepository, never()).save(any(), any());
		verifyZeroInteractions(this.successHandler);
	}

	@Test
	public void filterWhenConvertAndAuthenticationExceptionThenServerError() {
		Mono<Authentication> authentication = Mono.just(new TestingAuthenticationToken("test", "this", "ROLE_USER"));
		when(this.authenticationConverter.convert(any())).thenReturn(authentication);
		when(this.authenticationManager.authenticate(any())).thenReturn(Mono.error(new RuntimeException("Failed")));

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(this.filter)
			.build();

		client
			.get()
			.uri("/")
			.exchange()
			.expectStatus().is5xxServerError()
			.expectBody().isEmpty();

		verify(this.securityContextRepository, never()).save(any(), any());
		verifyZeroInteractions(this.successHandler, this.failureHandler);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setRequiresAuthenticationMatcherWhenNullThenException() {
		this.filter.setRequiresAuthenticationMatcher(null);
	}
}
