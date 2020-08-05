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

import org.junit.Test;
import reactor.core.publisher.Mono;

import org.springframework.core.ResolvableType;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.util.MimeType;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 */
public class BasicAuthenticationDecoderTests {

	@Test
	public void basicAuthenticationWhenEncodedThenDecodes() {
		BasicAuthenticationEncoder encoder = new BasicAuthenticationEncoder();
		BasicAuthenticationDecoder decoder = new BasicAuthenticationDecoder();
		UsernamePasswordMetadata expectedCredentials = new UsernamePasswordMetadata("rob", "password");
		DefaultDataBufferFactory factory = new DefaultDataBufferFactory();
		ResolvableType elementType = ResolvableType.forClass(UsernamePasswordMetadata.class);
		MimeType mimeType = UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE;
		Map<String, Object> hints = null;

		DataBuffer dataBuffer = encoder.encodeValue(expectedCredentials, factory, elementType, mimeType, hints);
		UsernamePasswordMetadata actualCredentials = decoder
				.decodeToMono(Mono.just(dataBuffer), elementType, mimeType, hints).block();

		assertThat(actualCredentials).isEqualToComparingFieldByField(expectedCredentials);
	}

}