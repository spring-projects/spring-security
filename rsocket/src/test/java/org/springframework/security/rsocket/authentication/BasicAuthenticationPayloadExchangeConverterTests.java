/*
 * Copyright 2004-present the original author or authors.
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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.CompositeByteBuf;
import io.rsocket.Payload;
import io.rsocket.metadata.CompositeMetadataCodec;
import io.rsocket.metadata.WellKnownMimeType;
import io.rsocket.util.DefaultPayload;
import org.junit.jupiter.api.Test;

import org.springframework.core.ResolvableType;
import org.springframework.core.codec.DecodingException;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.core.io.buffer.NettyDataBufferFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.security.rsocket.api.PayloadExchangeType;
import org.springframework.security.rsocket.core.DefaultPayloadExchange;
import org.springframework.security.rsocket.metadata.BasicAuthenticationEncoder;
import org.springframework.security.rsocket.metadata.UsernamePasswordMetadata;
import org.springframework.util.MimeType;
import org.springframework.util.MimeTypeUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Rob Winch
 */
public class BasicAuthenticationPayloadExchangeConverterTests {

	private static final MimeType COMPOSITE_METADATA = MimeTypeUtils
		.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_COMPOSITE_METADATA.getString());

	private final BasicAuthenticationPayloadExchangeConverter converter = new BasicAuthenticationPayloadExchangeConverter();

	@Test
	public void convertWhenBasicCredentialsThenAuthenticates() {
		PayloadExchange exchange = createExchange(createRequestPayload());
		Authentication authentication = this.converter.convert(exchange).block();
		assertThat(authentication).isEqualTo(UsernamePasswordAuthenticationToken.unauthenticated("user", "password"));
	}

	@Test
	public void convertWhenNoBasicAuthenticationMetadataThenEmpty() {
		PayloadExchange exchange = createExchange(createRequestPayloadWithNoMetadata());
		assertThat(this.converter.convert(exchange).blockOptional()).isEmpty();
	}

	@Test
	public void convertWhenUsernameSizeExceedsLengthThenMalformed() {
		PayloadExchange exchange = createExchange(createMalformedRequestPayload());
		assertThatExceptionOfType(DecodingException.class).isThrownBy(() -> this.converter.convert(exchange).block());
	}

	private Payload createRequestPayload() {
		UsernamePasswordMetadata credentials = new UsernamePasswordMetadata("user", "password");
		BasicAuthenticationEncoder encoder = new BasicAuthenticationEncoder();
		DefaultDataBufferFactory factory = new DefaultDataBufferFactory();
		ResolvableType elementType = ResolvableType.forClass(UsernamePasswordMetadata.class);
		MimeType mimeType = UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE;
		DataBuffer dataBuffer = encoder.encodeValue(credentials, factory, elementType, mimeType, null);
		return createRequestPayload(NettyDataBufferFactory.toByteBuf(dataBuffer));
	}

	private Payload createMalformedRequestPayload() {
		byte[] maliciousSize = { 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff }; // Integer.MAX_VALUE
		ByteBuf rawMetadata = ByteBufAllocator.DEFAULT.buffer();
		rawMetadata.writeBytes(maliciousSize);
		return createRequestPayload(rawMetadata);
	}

	private Payload createRequestPayload(ByteBuf rawMetadata) {
		MimeType mimeType = UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE;
		ByteBufAllocator allocator = ByteBufAllocator.DEFAULT;
		CompositeByteBuf metadata = allocator.compositeBuffer();
		CompositeMetadataCodec.encodeAndAddMetadata(metadata, allocator, mimeType.toString(), rawMetadata);
		return DefaultPayload.create(allocator.buffer(), metadata);
	}

	private Payload createRequestPayloadWithNoMetadata() {
		ByteBufAllocator allocator = ByteBufAllocator.DEFAULT;
		CompositeByteBuf metadata = allocator.compositeBuffer();
		return DefaultPayload.create(allocator.buffer(), metadata);
	}

	private PayloadExchange createExchange(Payload payload) {
		return new DefaultPayloadExchange(PayloadExchangeType.REQUEST_RESPONSE, payload, COMPOSITE_METADATA,
				MediaType.APPLICATION_JSON);
	}

}
