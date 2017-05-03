/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.springframework.security.web.server.authentication;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.web.server.AuthenticationEntryPoint;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.basicAuthentication;


/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthenticationWebFilterTests {
	@Mock
	AuthenticationSuccessHandler successHandler;
	@Mock
	Function<ServerWebExchange,Mono<Authentication>> authenticationConverter;
	@Mock
	ReactiveAuthenticationManager authenticationManager;
	@Mock
	AuthenticationEntryPoint entryPoint;

	AuthenticationWebFilter filter;

	@Before
	public void setup() {
		filter = new AuthenticationWebFilter(authenticationManager);
		filter.setAuthenticationSuccessHandler(successHandler);
		filter.setAuthenticationConverter(authenticationConverter);
		filter.setEntryPoint(entryPoint);
	}

	@Test
	public void filterWhenDefaultsAndNoAuthenticationThenContinues() {
		filter = new AuthenticationWebFilter(authenticationManager);

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(filter)
			.build();

		EntityExchangeResult<byte[]> result = client.get()
			.uri("/")
			.exchange()
			.expectStatus().isOk()
			.expectBody().consumeAsStringWith(b -> assertThat(b).isEqualTo("ok"))
			.returnResult();

		verifyZeroInteractions(authenticationManager);
		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenDefaultsAndAuthenticationSuccessThenContinues() {
		when(authenticationManager.authenticate(any())).thenReturn(Mono.just(new TestingAuthenticationToken("test","this", "ROLE")));
		filter = new AuthenticationWebFilter(authenticationManager);

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(filter)
			.build();

		EntityExchangeResult<byte[]> result = client
			.filter(basicAuthentication("test","this"))
			.get()
			.uri("/")
			.exchange()
			.expectStatus().isOk()
			.expectBody().consumeAsStringWith(b -> assertThat(b).isEqualTo("ok"))
			.returnResult();

		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenDefaultsAndAuthenticationFailThenUnauthorized() {
		when(authenticationManager.authenticate(any())).thenReturn(Mono.error(new BadCredentialsException("failed")));
		filter = new AuthenticationWebFilter(authenticationManager);

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(filter)
			.build();

		EntityExchangeResult<Void> result = client
			.filter(basicAuthentication("test", "this"))
			.get()
			.uri("/")
			.exchange()
			.expectStatus().isUnauthorized()
			.expectHeader().valueMatches("WWW-Authenticate", "Basic realm=\"Realm\"")
			.expectBody().isEmpty();

		assertThat(result.getResponseCookies()).isEmpty();
	}

	@Test
	public void filterWhenConvertEmptyThenOk() {
		when(authenticationConverter.apply(any())).thenReturn(Mono.empty());

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(filter)
			.build();

		EntityExchangeResult<byte[]> result = client
			.get()
			.uri("/")
			.exchange()
			.expectStatus().isOk()
			.expectBody().consumeAsStringWith(b -> assertThat(b).isEqualTo("ok"))
			.returnResult();

		verifyZeroInteractions(authenticationManager, successHandler, entryPoint);
	}

	@Test
	public void filterWhenConvertErrorThenServerError() {
		when(authenticationConverter.apply(any())).thenReturn(Mono.error(new RuntimeException("Unexpected")));

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(filter)
			.build();

		client
			.get()
			.uri("/")
			.exchange()
			.expectStatus().is5xxServerError()
			.expectBody().isEmpty();

		verifyZeroInteractions(authenticationManager, successHandler, entryPoint);
	}

	@Test
	public void filterWhenConvertAndAuthenticationSuccessThenSuccessHandler() {
		Mono<Authentication> authentication = Mono.just(new TestingAuthenticationToken("test", "this", "ROLE_USER"));
		when(authenticationConverter.apply(any())).thenReturn(authentication);
		when(authenticationManager.authenticate(any())).thenReturn(authentication);
		when(successHandler.success(any(),any(),any())).thenReturn(Mono.empty());

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(filter)
			.build();

		client
			.get()
			.uri("/")
			.exchange()
			.expectStatus().isOk()
			.expectBody().isEmpty();

		verify(successHandler).success(eq(authentication.block()), any(), any());
		verifyZeroInteractions(entryPoint);
	}

	@Test
	public void filterWhenConvertAndAuthenticationFailThenEntryPoint() {
		Mono<Authentication> authentication = Mono.just(new TestingAuthenticationToken("test", "this", "ROLE_USER"));
		when(authenticationConverter.apply(any())).thenReturn(authentication);
		when(authenticationManager.authenticate(any())).thenReturn(Mono.error(new BadCredentialsException("Failed")));
		when(entryPoint.commence(any(),any())).thenReturn(Mono.empty());

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(filter)
			.build();

		client
			.get()
			.uri("/")
			.exchange()
			.expectStatus().isOk()
			.expectBody().isEmpty();

		verify(entryPoint).commence(any(),any());
		verifyZeroInteractions(successHandler);
	}

	@Test
	public void filterWhenConvertAndAuthenticationExceptionThenServerError() {
		Mono<Authentication> authentication = Mono.just(new TestingAuthenticationToken("test", "this", "ROLE_USER"));
		when(authenticationConverter.apply(any())).thenReturn(authentication);
		when(authenticationManager.authenticate(any())).thenReturn(Mono.error(new RuntimeException("Failed")));
		when(entryPoint.commence(any(),any())).thenReturn(Mono.empty());

		WebTestClient client = WebTestClientBuilder
			.bindToWebFilters(filter)
			.build();

		client
			.get()
			.uri("/")
			.exchange()
			.expectStatus().is5xxServerError()
			.expectBody().isEmpty();

		verifyZeroInteractions(successHandler, entryPoint);
	}
}
