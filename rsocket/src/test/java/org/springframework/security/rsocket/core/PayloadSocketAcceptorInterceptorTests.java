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
import org.springframework.http.MediaType;
import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.security.rsocket.api.PayloadInterceptor;
import org.springframework.security.rsocket.core.PayloadInterceptorRSocket;
import org.springframework.security.rsocket.core.PayloadSocketAcceptorInterceptor;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class PayloadSocketAcceptorInterceptorTests {
	@Mock
	private PayloadInterceptor interceptor;

	@Mock
	private SocketAcceptor socketAcceptor;

	@Mock
	private ConnectionSetupPayload setupPayload;

	@Mock
	private RSocket rSocket;

	@Mock
	private Payload payload;

	private List<PayloadInterceptor> interceptors;

	private PayloadSocketAcceptorInterceptor acceptorInterceptor;

	@Before
	public void setup() {
		this.interceptors = Arrays.asList(this.interceptor);
		this.acceptorInterceptor = new PayloadSocketAcceptorInterceptor(this.interceptors);
	}

	@Test
	public void applyWhenDefaultMetadataMimeTypeThenDefaulted() {
		when(this.setupPayload.dataMimeType()).thenReturn(MediaType.APPLICATION_JSON_VALUE);

		PayloadExchange exchange = captureExchange();

		assertThat(exchange.getMetadataMimeType().toString()).isEqualTo(WellKnownMimeType.MESSAGE_RSOCKET_COMPOSITE_METADATA.getString());
		assertThat(exchange.getDataMimeType()).isEqualTo(MediaType.APPLICATION_JSON);
	}

	@Test
	public void acceptWhenDefaultMetadataMimeTypeOverrideThenDefaulted() {
		this.acceptorInterceptor.setDefaultMetadataMimeType(MediaType.APPLICATION_JSON);
		when(this.setupPayload.dataMimeType()).thenReturn(MediaType.APPLICATION_JSON_VALUE);

		PayloadExchange exchange = captureExchange();

		assertThat(exchange.getMetadataMimeType()).isEqualTo(MediaType.APPLICATION_JSON);
		assertThat(exchange.getDataMimeType()).isEqualTo(MediaType.APPLICATION_JSON);
	}

	@Test
	public void acceptWhenDefaultDataMimeTypeThenDefaulted() {
		this.acceptorInterceptor.setDefaultDataMimeType(MediaType.APPLICATION_JSON);

		PayloadExchange exchange = captureExchange();

		assertThat(exchange.getMetadataMimeType().toString()).isEqualTo(WellKnownMimeType.MESSAGE_RSOCKET_COMPOSITE_METADATA.getString());
		assertThat(exchange.getDataMimeType()).isEqualTo(MediaType.APPLICATION_JSON);
	}

	private PayloadExchange captureExchange() {
		when(this.socketAcceptor.accept(any(), any())).thenReturn(Mono.just(this.rSocket));
		when(this.interceptor.intercept(any(), any())).thenReturn(Mono.empty());

		SocketAcceptor wrappedAcceptor = this.acceptorInterceptor.apply(this.socketAcceptor);
		RSocket result = wrappedAcceptor.accept(this.setupPayload, this.rSocket).block();

		assertThat(result).isInstanceOf(PayloadInterceptorRSocket.class);

		when(this.rSocket.fireAndForget(any())).thenReturn(Mono.empty());

		result.fireAndForget(this.payload).block();

		ArgumentCaptor<PayloadExchange> exchangeArg =
				ArgumentCaptor.forClass(PayloadExchange.class);
		verify(this.interceptor, times(2)).intercept(exchangeArg.capture(), any());
		return exchangeArg.getValue();
	}
}
