/*
 * Copyright 2019 the original author or authors.
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

package org.springframework.security.rsocket.core;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import io.rsocket.ConnectionSetupPayload;
import io.rsocket.Payload;
import io.rsocket.RSocket;
import io.rsocket.SocketAcceptor;
import io.rsocket.metadata.WellKnownMimeType;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.security.rsocket.api.PayloadInterceptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class PayloadSocketAcceptorTests {

	private PayloadSocketAcceptor acceptor;

	private List<PayloadInterceptor> interceptors;

	@Mock
	private SocketAcceptor delegate;

	@Mock
	private PayloadInterceptor interceptor;

	@Mock
	private ConnectionSetupPayload setupPayload;

	@Mock
	private RSocket rSocket;

	@Mock
	private Payload payload;

	@Before
	public void setup() {
		this.interceptors = Arrays.asList(this.interceptor);
		this.acceptor = new PayloadSocketAcceptor(this.delegate, this.interceptors);
	}

	@Test
	public void constructorWhenNullDelegateThenException() {
		this.delegate = null;
		assertThatCode(() -> new PayloadSocketAcceptor(this.delegate, this.interceptors));
	}

	@Test
	public void constructorWhenNullInterceptorsThenException() {
		this.interceptors = null;
		assertThatCode(() -> new PayloadSocketAcceptor(this.delegate, this.interceptors));
	}

	@Test
	public void constructorWhenEmptyInterceptorsThenException() {
		this.interceptors = Collections.emptyList();
		assertThatCode(() -> new PayloadSocketAcceptor(this.delegate, this.interceptors));
	}

	@Test
	public void acceptWhenDataMimeTypeNullThenException() {
		assertThatCode(() -> this.acceptor.accept(this.setupPayload, this.rSocket).block())
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void acceptWhenDefaultMetadataMimeTypeThenDefaulted() {
		when(this.setupPayload.dataMimeType()).thenReturn(MediaType.APPLICATION_JSON_VALUE);

		PayloadExchange exchange = captureExchange();

		assertThat(exchange.getMetadataMimeType().toString())
				.isEqualTo(WellKnownMimeType.MESSAGE_RSOCKET_COMPOSITE_METADATA.getString());
		assertThat(exchange.getDataMimeType()).isEqualTo(MediaType.APPLICATION_JSON);
	}

	@Test
	public void acceptWhenDefaultMetadataMimeTypeOverrideThenDefaulted() {
		this.acceptor.setDefaultMetadataMimeType(MediaType.APPLICATION_JSON);
		when(this.setupPayload.dataMimeType()).thenReturn(MediaType.APPLICATION_JSON_VALUE);

		PayloadExchange exchange = captureExchange();

		assertThat(exchange.getMetadataMimeType()).isEqualTo(MediaType.APPLICATION_JSON);
		assertThat(exchange.getDataMimeType()).isEqualTo(MediaType.APPLICATION_JSON);
	}

	@Test
	public void acceptWhenDefaultDataMimeTypeThenDefaulted() {
		this.acceptor.setDefaultDataMimeType(MediaType.APPLICATION_JSON);

		PayloadExchange exchange = captureExchange();

		assertThat(exchange.getMetadataMimeType().toString())
				.isEqualTo(WellKnownMimeType.MESSAGE_RSOCKET_COMPOSITE_METADATA.getString());
		assertThat(exchange.getDataMimeType()).isEqualTo(MediaType.APPLICATION_JSON);
	}

	@Test
	public void acceptWhenExplicitMimeTypeThenThenOverrideDefault() {
		when(this.setupPayload.metadataMimeType()).thenReturn(MediaType.TEXT_PLAIN_VALUE);
		when(this.setupPayload.dataMimeType()).thenReturn(MediaType.APPLICATION_JSON_VALUE);

		PayloadExchange exchange = captureExchange();

		assertThat(exchange.getMetadataMimeType()).isEqualTo(MediaType.TEXT_PLAIN);
		assertThat(exchange.getDataMimeType()).isEqualTo(MediaType.APPLICATION_JSON);
	}

	@Test
	// gh-8654
	public void acceptWhenDelegateAcceptRequiresReactiveSecurityContext() {
		when(this.setupPayload.metadataMimeType()).thenReturn(MediaType.TEXT_PLAIN_VALUE);
		when(this.setupPayload.dataMimeType()).thenReturn(MediaType.APPLICATION_JSON_VALUE);
		SecurityContext expectedSecurityContext = new SecurityContextImpl(
				new TestingAuthenticationToken("user", "password", "ROLE_USER"));
		CaptureSecurityContextSocketAcceptor captureSecurityContext = new CaptureSecurityContextSocketAcceptor(
				this.rSocket);
		PayloadInterceptor authenticateInterceptor = (exchange, chain) -> {
			Context withSecurityContext = ReactiveSecurityContextHolder
					.withSecurityContext(Mono.just(expectedSecurityContext));
			return chain.next(exchange).subscriberContext(withSecurityContext);
		};
		List<PayloadInterceptor> interceptors = Arrays.asList(authenticateInterceptor);
		this.acceptor = new PayloadSocketAcceptor(captureSecurityContext, interceptors);

		this.acceptor.accept(this.setupPayload, this.rSocket).block();

		assertThat(captureSecurityContext.getSecurityContext()).isEqualTo(expectedSecurityContext);
	}

	private PayloadExchange captureExchange() {
		when(this.delegate.accept(any(), any())).thenReturn(Mono.just(this.rSocket));
		when(this.interceptor.intercept(any(), any())).thenReturn(Mono.empty());

		RSocket result = this.acceptor.accept(this.setupPayload, this.rSocket).block();

		assertThat(result).isInstanceOf(PayloadInterceptorRSocket.class);

		when(this.rSocket.fireAndForget(any())).thenReturn(Mono.empty());

		result.fireAndForget(this.payload).block();

		ArgumentCaptor<PayloadExchange> exchangeArg = ArgumentCaptor.forClass(PayloadExchange.class);
		verify(this.interceptor, times(2)).intercept(exchangeArg.capture(), any());
		return exchangeArg.getValue();
	}

}
