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

import org.reactivestreams.Publisher;
import org.springframework.core.ResolvableType;
import org.springframework.core.codec.AbstractDecoder;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.util.MimeType;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Decodes {@link UsernamePasswordMetadata#BASIC_AUTHENTICATION_MIME_TYPE}
 *
 * @author Rob Winch
 * @since 5.2
 * @deprecated Basic Authentication did not evolve into a standard. Use Simple
 * Authentication instead.
 */
@Deprecated
public class BasicAuthenticationDecoder extends AbstractDecoder<UsernamePasswordMetadata> {

	public BasicAuthenticationDecoder() {
		super(UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE);
	}

	@Override
	public Flux<UsernamePasswordMetadata> decode(Publisher<DataBuffer> input, ResolvableType elementType,
			MimeType mimeType, Map<String, Object> hints) {
		return Flux.from(input).map(DataBuffer::asByteBuffer).map(byteBuffer -> {
			byte[] sizeBytes = new byte[4];
			byteBuffer.get(sizeBytes);

			int usernameSize = 4;
			byte[] usernameBytes = new byte[usernameSize];
			byteBuffer.get(usernameBytes);
			byte[] passwordBytes = new byte[byteBuffer.remaining()];
			byteBuffer.get(passwordBytes);
			String username = new String(usernameBytes);
			String password = new String(passwordBytes);
			return new UsernamePasswordMetadata(username, password);
		});
	}

	@Override
	public Mono<UsernamePasswordMetadata> decodeToMono(Publisher<DataBuffer> input, ResolvableType elementType,
			MimeType mimeType, Map<String, Object> hints) {
		return Mono.from(input).map(DataBuffer::asByteBuffer).map(byteBuffer -> {
			int usernameSize = byteBuffer.getInt();
			byte[] usernameBytes = new byte[usernameSize];
			byteBuffer.get(usernameBytes);
			byte[] passwordBytes = new byte[byteBuffer.remaining()];
			byteBuffer.get(passwordBytes);
			String username = new String(usernameBytes);
			String password = new String(passwordBytes);
			return new UsernamePasswordMetadata(username, password);
		});
	}

}
