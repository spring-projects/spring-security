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

import io.rsocket.Payload;
import io.rsocket.RSocket;
import io.rsocket.metadata.WellKnownMimeType;
import io.rsocket.util.RSocketProxy;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.publisher.PublisherProbe;
import reactor.test.publisher.TestPublisher;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.security.rsocket.api.PayloadExchangeType;
import org.springframework.security.rsocket.api.PayloadInterceptor;
import org.springframework.security.rsocket.api.PayloadInterceptorChain;
import org.springframework.util.MimeType;
import org.springframework.util.MimeTypeUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class PayloadInterceptorRSocketTests {

	static final MimeType COMPOSITE_METADATA = MimeTypeUtils
			.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_COMPOSITE_METADATA.getString());

	@Mock
	RSocket delegate;

	@Mock
	PayloadInterceptor interceptor;

	@Mock
	PayloadInterceptor interceptor2;

	@Mock
	Payload payload;

	@Captor
	private ArgumentCaptor<PayloadExchange> exchange;

	PublisherProbe<Void> voidResult = PublisherProbe.empty();

	TestPublisher<Payload> payloadResult = TestPublisher.createCold();

	private MimeType metadataMimeType = COMPOSITE_METADATA;

	private MimeType dataMimeType = MediaType.APPLICATION_JSON;

	@Test
	public void constructorWhenNullDelegateThenException() {
		this.delegate = null;
		List<PayloadInterceptor> interceptors = Arrays.asList(this.interceptor);
		assertThatCode(() -> {
			new PayloadInterceptorRSocket(this.delegate, interceptors, this.metadataMimeType, this.dataMimeType);
		}).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenNullInterceptorsThenException() {
		List<PayloadInterceptor> interceptors = null;
		assertThatCode(() -> new PayloadInterceptorRSocket(this.delegate, interceptors, this.metadataMimeType,
				this.dataMimeType)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenEmptyInterceptorsThenException() {
		List<PayloadInterceptor> interceptors = Collections.emptyList();
		assertThatCode(() -> new PayloadInterceptorRSocket(this.delegate, interceptors, this.metadataMimeType,
				this.dataMimeType)).isInstanceOf(IllegalArgumentException.class);
	}

	// single interceptor

	@Test
	public void fireAndForgetWhenInterceptorCompletesThenDelegateSubscribed() {
		given(this.interceptor.intercept(any(), any())).willAnswer(withChainNext());
		given(this.delegate.fireAndForget(any())).willReturn(this.voidResult.mono());

		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(this.delegate,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		StepVerifier.create(interceptor.fireAndForget(this.payload)).then(() -> this.voidResult.assertWasSubscribed())
				.verifyComplete();

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
	}

	@Test
	public void fireAndForgetWhenInterceptorErrorsThenDelegateNotSubscribed() {
		RuntimeException expected = new RuntimeException("Oops");
		given(this.interceptor.intercept(any(), any())).willReturn(Mono.error(expected));

		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(this.delegate,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		StepVerifier.create(interceptor.fireAndForget(this.payload))
				.then(() -> this.voidResult.assertWasNotSubscribed())
				.verifyErrorSatisfies((e) -> assertThat(e).isEqualTo(expected));

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
	}

	@Test
	public void fireAndForgetWhenSecurityContextThenDelegateContext() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");
		given(this.interceptor.intercept(any(), any())).willAnswer(withAuthenticated(authentication));
		given(this.delegate.fireAndForget(any())).willReturn(Mono.empty());

		RSocket assertAuthentication = new RSocketProxy(this.delegate) {
			@Override
			public Mono<Void> fireAndForget(Payload payload) {
				return assertAuthentication(authentication).flatMap((a) -> super.fireAndForget(payload));
			}
		};
		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(assertAuthentication,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		interceptor.fireAndForget(this.payload).block();

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
		verify(this.delegate).fireAndForget(this.payload);
	}

	@Test
	public void requestResponseWhenInterceptorCompletesThenDelegateSubscribed() {
		given(this.interceptor.intercept(any(), any())).willReturn(Mono.empty());
		given(this.delegate.requestResponse(any())).willReturn(this.payloadResult.mono());

		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(this.delegate,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		StepVerifier.create(interceptor.requestResponse(this.payload))
				.then(() -> this.payloadResult.assertSubscribers()).then(() -> this.payloadResult.emit(this.payload))
				.expectNext(this.payload).verifyComplete();

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
		verify(this.delegate).requestResponse(this.payload);
	}

	@Test
	public void requestResponseWhenInterceptorErrorsThenDelegateNotInvoked() {
		RuntimeException expected = new RuntimeException("Oops");
		given(this.interceptor.intercept(any(), any())).willReturn(Mono.error(expected));

		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(this.delegate,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		assertThatCode(() -> interceptor.requestResponse(this.payload).block()).isEqualTo(expected);

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
		verifyZeroInteractions(this.delegate);
	}

	@Test
	public void requestResponseWhenSecurityContextThenDelegateContext() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");
		given(this.interceptor.intercept(any(), any())).willAnswer(withAuthenticated(authentication));
		given(this.delegate.requestResponse(any())).willReturn(this.payloadResult.mono());

		RSocket assertAuthentication = new RSocketProxy(this.delegate) {
			@Override
			public Mono<Payload> requestResponse(Payload payload) {
				return assertAuthentication(authentication).flatMap((a) -> super.requestResponse(payload));
			}
		};
		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(assertAuthentication,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		StepVerifier.create(interceptor.requestResponse(this.payload))
				.then(() -> this.payloadResult.assertSubscribers()).then(() -> this.payloadResult.emit(this.payload))
				.expectNext(this.payload).verifyComplete();

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
		verify(this.delegate).requestResponse(this.payload);
	}

	@Test
	public void requestStreamWhenInterceptorCompletesThenDelegateSubscribed() {
		given(this.interceptor.intercept(any(), any())).willReturn(Mono.empty());
		given(this.delegate.requestStream(any())).willReturn(this.payloadResult.flux());

		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(this.delegate,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		StepVerifier.create(interceptor.requestStream(this.payload)).then(() -> this.payloadResult.assertSubscribers())
				.then(() -> this.payloadResult.emit(this.payload)).expectNext(this.payload).verifyComplete();

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
	}

	@Test
	public void requestStreamWhenInterceptorErrorsThenDelegateNotSubscribed() {
		RuntimeException expected = new RuntimeException("Oops");
		given(this.interceptor.intercept(any(), any())).willReturn(Mono.error(expected));

		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(this.delegate,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		StepVerifier.create(interceptor.requestStream(this.payload))
				.then(() -> this.payloadResult.assertNoSubscribers())
				.verifyErrorSatisfies((e) -> assertThat(e).isEqualTo(expected));

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
	}

	@Test
	public void requestStreamWhenSecurityContextThenDelegateContext() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");
		given(this.interceptor.intercept(any(), any())).willAnswer(withAuthenticated(authentication));
		given(this.delegate.requestStream(any())).willReturn(this.payloadResult.flux());

		RSocket assertAuthentication = new RSocketProxy(this.delegate) {
			@Override
			public Flux<Payload> requestStream(Payload payload) {
				return assertAuthentication(authentication).flatMapMany((a) -> super.requestStream(payload));
			}
		};
		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(assertAuthentication,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		StepVerifier.create(interceptor.requestStream(this.payload)).then(() -> this.payloadResult.assertSubscribers())
				.then(() -> this.payloadResult.emit(this.payload)).expectNext(this.payload).verifyComplete();

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
		verify(this.delegate).requestStream(this.payload);
	}

	@Test
	public void requestChannelWhenInterceptorCompletesThenDelegateSubscribed() {
		given(this.interceptor.intercept(any(), any())).willReturn(Mono.empty());
		given(this.delegate.requestChannel(any())).willReturn(this.payloadResult.flux());

		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(this.delegate,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		StepVerifier.create(interceptor.requestChannel(Flux.just(this.payload)))
				.then(() -> this.payloadResult.assertSubscribers()).then(() -> this.payloadResult.emit(this.payload))
				.expectNext(this.payload).verifyComplete();

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
		verify(this.delegate).requestChannel(any());
	}

	@Test
	public void requestChannelWhenInterceptorErrorsThenDelegateNotSubscribed() {
		RuntimeException expected = new RuntimeException("Oops");
		given(this.interceptor.intercept(any(), any())).willReturn(Mono.error(expected));

		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(this.delegate,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		StepVerifier.create(interceptor.requestChannel(Flux.just(this.payload)))
				.then(() -> this.payloadResult.assertNoSubscribers())
				.verifyErrorSatisfies((e) -> assertThat(e).isEqualTo(expected));

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
	}

	@Test
	public void requestChannelWhenSecurityContextThenDelegateContext() {
		Mono<Payload> payload = Mono.just(this.payload);
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");
		given(this.interceptor.intercept(any(), any())).willAnswer(withAuthenticated(authentication));
		given(this.delegate.requestChannel(any())).willReturn(this.payloadResult.flux());

		RSocket assertAuthentication = new RSocketProxy(this.delegate) {
			@Override
			public Flux<Payload> requestChannel(Publisher<Payload> payload) {
				return assertAuthentication(authentication).flatMapMany((a) -> super.requestChannel(payload));
			}
		};
		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(assertAuthentication,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		StepVerifier.create(interceptor.requestChannel(payload)).then(() -> this.payloadResult.assertSubscribers())
				.then(() -> this.payloadResult.emit(this.payload)).expectNext(this.payload).verifyComplete();

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
		verify(this.delegate).requestChannel(any());
	}

	@Test
	public void metadataPushWhenInterceptorCompletesThenDelegateSubscribed() {
		given(this.interceptor.intercept(any(), any())).willReturn(Mono.empty());
		given(this.delegate.metadataPush(any())).willReturn(this.voidResult.mono());

		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(this.delegate,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		StepVerifier.create(interceptor.metadataPush(this.payload)).then(() -> this.voidResult.assertWasSubscribed())
				.verifyComplete();

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
	}

	@Test
	public void metadataPushWhenInterceptorErrorsThenDelegateNotSubscribed() {
		RuntimeException expected = new RuntimeException("Oops");
		given(this.interceptor.intercept(any(), any())).willReturn(Mono.error(expected));

		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(this.delegate,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		StepVerifier.create(interceptor.metadataPush(this.payload)).then(() -> this.voidResult.assertWasNotSubscribed())
				.verifyErrorSatisfies((e) -> assertThat(e).isEqualTo(expected));

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
	}

	@Test
	public void metadataPushWhenSecurityContextThenDelegateContext() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");
		given(this.interceptor.intercept(any(), any())).willAnswer(withAuthenticated(authentication));
		given(this.delegate.metadataPush(any())).willReturn(this.voidResult.mono());

		RSocket assertAuthentication = new RSocketProxy(this.delegate) {
			@Override
			public Mono<Void> metadataPush(Payload payload) {
				return assertAuthentication(authentication).flatMap((a) -> super.metadataPush(payload));
			}
		};
		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(assertAuthentication,
				Arrays.asList(this.interceptor), this.metadataMimeType, this.dataMimeType);

		StepVerifier.create(interceptor.metadataPush(this.payload)).verifyComplete();

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
		verify(this.delegate).metadataPush(this.payload);
		this.voidResult.assertWasSubscribed();
	}

	// multiple interceptors

	@Test
	public void fireAndForgetWhenInterceptorsCompleteThenDelegateInvoked() {
		given(this.interceptor.intercept(any(), any())).willAnswer(withChainNext());
		given(this.interceptor2.intercept(any(), any())).willAnswer(withChainNext());
		given(this.delegate.fireAndForget(any())).willReturn(this.voidResult.mono());

		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(this.delegate,
				Arrays.asList(this.interceptor, this.interceptor2), this.metadataMimeType, this.dataMimeType);

		interceptor.fireAndForget(this.payload).block();

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
		this.voidResult.assertWasSubscribed();
	}

	@Test
	public void fireAndForgetWhenInterceptorsMutatesPayloadThenDelegateInvoked() {
		given(this.interceptor.intercept(any(), any())).willAnswer(withChainNext());
		given(this.interceptor2.intercept(any(), any())).willAnswer(withChainNext());
		given(this.delegate.fireAndForget(any())).willReturn(this.voidResult.mono());

		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(this.delegate,
				Arrays.asList(this.interceptor, this.interceptor2), this.metadataMimeType, this.dataMimeType);

		interceptor.fireAndForget(this.payload).block();

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
		verify(this.interceptor2).intercept(any(), any());
		verify(this.delegate).fireAndForget(eq(this.payload));
		this.voidResult.assertWasSubscribed();
	}

	@Test
	public void fireAndForgetWhenInterceptor1ErrorsThenInterceptor2AndDelegateNotInvoked() {
		RuntimeException expected = new RuntimeException("Oops");
		given(this.interceptor.intercept(any(), any())).willReturn(Mono.error(expected));

		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(this.delegate,
				Arrays.asList(this.interceptor, this.interceptor2), this.metadataMimeType, this.dataMimeType);

		assertThatCode(() -> interceptor.fireAndForget(this.payload).block()).isEqualTo(expected);

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
		verifyZeroInteractions(this.interceptor2);
		this.voidResult.assertWasNotSubscribed();
	}

	@Test
	public void fireAndForgetWhenInterceptor2ErrorsThenInterceptor2AndDelegateNotInvoked() {
		RuntimeException expected = new RuntimeException("Oops");
		given(this.interceptor.intercept(any(), any())).willAnswer(withChainNext());
		given(this.interceptor2.intercept(any(), any())).willReturn(Mono.error(expected));

		PayloadInterceptorRSocket interceptor = new PayloadInterceptorRSocket(this.delegate,
				Arrays.asList(this.interceptor, this.interceptor2), this.metadataMimeType, this.dataMimeType);

		assertThatCode(() -> interceptor.fireAndForget(this.payload).block()).isEqualTo(expected);

		verify(this.interceptor).intercept(this.exchange.capture(), any());
		assertThat(this.exchange.getValue().getPayload()).isEqualTo(this.payload);
		verify(this.interceptor2).intercept(any(), any());
		this.voidResult.assertWasNotSubscribed();
	}

	private Mono<Authentication> assertAuthentication(Authentication authentication) {
		return ReactiveSecurityContextHolder.getContext().map(SecurityContext::getAuthentication)
				.doOnNext((a) -> assertThat(a).isEqualTo(authentication));
	}

	private Answer<Object> withAuthenticated(Authentication authentication) {
		return (invocation) -> {
			PayloadInterceptorChain c = (PayloadInterceptorChain) invocation.getArguments()[1];
			return c.next(new DefaultPayloadExchange(PayloadExchangeType.REQUEST_CHANNEL, this.payload,
					this.metadataMimeType, this.dataMimeType))
					.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));
		};
	}

	private static Answer<Mono<Void>> withChainNext() {
		return (invocation) -> {
			PayloadExchange exchange = (PayloadExchange) invocation.getArguments()[0];
			PayloadInterceptorChain chain = (PayloadInterceptorChain) invocation.getArguments()[1];
			return chain.next(exchange);
		};
	}

}
