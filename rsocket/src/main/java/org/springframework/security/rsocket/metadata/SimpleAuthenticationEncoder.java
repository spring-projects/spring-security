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

package org.springframework.security.rsocket.metadata;

import java.util.Map;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.rsocket.metadata.AuthMetadataCodec;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;

import org.springframework.core.ResolvableType;
import org.springframework.core.codec.AbstractEncoder;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.NettyDataBufferFactory;
import org.springframework.util.MimeType;
import org.springframework.util.MimeTypeUtils;

/**
 * Encodes <a href=
 * "https://github.com/rsocket/rsocket/blob/5920ed374d008abb712cb1fd7c9d91778b2f4a68/Extensions/Security/Simple.md">Simple</a>
 * Authentication.
 *
 * @author Rob Winch
 * @since 5.3
 */
public class SimpleAuthenticationEncoder extends AbstractEncoder<UsernamePasswordMetadata> {

	private static final MimeType AUTHENTICATION_MIME_TYPE = MimeTypeUtils
			.parseMimeType("message/x.rsocket.authentication.v0");

	private NettyDataBufferFactory defaultBufferFactory = new NettyDataBufferFactory(ByteBufAllocator.DEFAULT);

	public SimpleAuthenticationEncoder() {
		super(AUTHENTICATION_MIME_TYPE);
	}

	@Override
	public Flux<DataBuffer> encode(Publisher<? extends UsernamePasswordMetadata> inputStream,
			DataBufferFactory bufferFactory, ResolvableType elementType, MimeType mimeType, Map<String, Object> hints) {
		return Flux.from(inputStream)
				.map(credentials -> encodeValue(credentials, bufferFactory, elementType, mimeType, hints));
	}

	@Override
	public DataBuffer encodeValue(UsernamePasswordMetadata credentials, DataBufferFactory bufferFactory,
			ResolvableType valueType, MimeType mimeType, Map<String, Object> hints) {
		String username = credentials.getUsername();
		String password = credentials.getPassword();
		NettyDataBufferFactory factory = nettyFactory(bufferFactory);
		ByteBufAllocator allocator = factory.getByteBufAllocator();
		ByteBuf simpleAuthentication = AuthMetadataCodec.encodeSimpleMetadata(allocator, username.toCharArray(),
				password.toCharArray());
		return factory.wrap(simpleAuthentication);
	}

	private NettyDataBufferFactory nettyFactory(DataBufferFactory bufferFactory) {
		if (bufferFactory instanceof NettyDataBufferFactory) {
			return (NettyDataBufferFactory) bufferFactory;
		}
		return this.defaultBufferFactory;
	}

}
