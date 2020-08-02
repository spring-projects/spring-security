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

package org.springframework.security.rsocket.authentication;

import java.util.Map;

import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.CompositeByteBuf;
import io.rsocket.Payload;
import io.rsocket.metadata.CompositeMetadataFlyweight;
import io.rsocket.metadata.WellKnownMimeType;
import io.rsocket.util.DefaultPayload;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.publisher.PublisherProbe;

import org.springframework.core.ResolvableType;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.core.io.buffer.NettyDataBufferFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.security.rsocket.api.PayloadExchangeType;
import org.springframework.security.rsocket.api.PayloadInterceptorChain;
import org.springframework.security.rsocket.core.DefaultPayloadExchange;
import org.springframework.security.rsocket.metadata.BasicAuthenticationEncoder;
import org.springframework.security.rsocket.metadata.UsernamePasswordMetadata;
import org.springframework.util.MimeType;
import org.springframework.util.MimeTypeUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthenticationPayloadInterceptorTests {

	static final MimeType COMPOSITE_METADATA = MimeTypeUtils
			.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_COMPOSITE_METADATA.getString());

	@Mock
	ReactiveAuthenticationManager authenticationManager;

	@Captor
	ArgumentCaptor<Authentication> authenticationArg;

	@Test
	public void constructorWhenAuthenticationManagerNullThenException() {
		assertThatCode(() -> new AuthenticationPayloadInterceptor(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void interceptWhenBasicCredentialsThenAuthenticates() {
		AuthenticationPayloadInterceptor interceptor = new AuthenticationPayloadInterceptor(this.authenticationManager);
		PayloadExchange exchange = createExchange();
		TestingAuthenticationToken expectedAuthentication = new TestingAuthenticationToken("user", "password");
		given(this.authenticationManager.authenticate(any())).willReturn(Mono.just(expectedAuthentication));
		AuthenticationPayloadInterceptorChain authenticationPayloadChain = new AuthenticationPayloadInterceptorChain();
		interceptor.intercept(exchange, authenticationPayloadChain).block();
		Authentication authentication = authenticationPayloadChain.getAuthentication();
		verify(this.authenticationManager).authenticate(this.authenticationArg.capture());
		assertThat(this.authenticationArg.getValue())
				.isEqualToComparingFieldByField(new UsernamePasswordAuthenticationToken("user", "password"));
		assertThat(authentication).isEqualTo(expectedAuthentication);
	}

	@Test
	public void interceptWhenAuthenticationSuccessThenChainSubscribedOnce() {
		AuthenticationPayloadInterceptor interceptor = new AuthenticationPayloadInterceptor(this.authenticationManager);
		PayloadExchange exchange = createExchange();
		TestingAuthenticationToken expectedAuthentication = new TestingAuthenticationToken("user", "password");
		given(this.authenticationManager.authenticate(any())).willReturn(Mono.just(expectedAuthentication));
		PublisherProbe<Void> voidResult = PublisherProbe.empty();
		PayloadInterceptorChain chain = mock(PayloadInterceptorChain.class);
		given(chain.next(any())).willReturn(voidResult.mono());
		StepVerifier.create(interceptor.intercept(exchange, chain))
				.then(() -> assertThat(voidResult.subscribeCount()).isEqualTo(1)).verifyComplete();
	}

	private Payload createRequestPayload() {
		UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("user", "password");
		BasicAuthenticationEncoder encoder = new BasicAuthenticationEncoder();
		DefaultDataBufferFactory factory = new DefaultDataBufferFactory();
		ResolvableType elementType = ResolvableType.forClass(UsernamePasswordMetadata.class);
		MimeType mimeType = UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE;
		Map<String, Object> hints = null;
		DataBuffer dataBuffer = encoder.encodeValue(credentials, factory, elementType, mimeType, hints);
		ByteBufAllocator allocator = ByteBufAllocator.DEFAULT;
		CompositeByteBuf metadata = allocator.compositeBuffer();
		CompositeMetadataFlyweight.encodeAndAddMetadata(metadata, allocator, mimeType.toString(),
				NettyDataBufferFactory.toByteBuf(dataBuffer));
		return DefaultPayload.create(allocator.buffer(), metadata);
	}

	private PayloadExchange createExchange() {
		return new DefaultPayloadExchange(PayloadExchangeType.REQUEST_RESPONSE, createRequestPayload(),
				COMPOSITE_METADATA, MediaType.APPLICATION_JSON);
	}

}
