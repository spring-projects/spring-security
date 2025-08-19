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

package org.springframework.security.config.web.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.core.ResolvableType;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.codec.HttpMessageEncoder;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.lang.NonNull;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.util.MimeType;

class OAuth2ErrorEncoder implements HttpMessageEncoder<OAuth2Error> {

	private final HttpMessageConverter<Object> messageConverter = HttpMessageConverters.getJsonMessageConverter();

	@NonNull
	@Override
	public List<MediaType> getStreamingMediaTypes() {
		return List.of();
	}

	@Override
	public boolean canEncode(ResolvableType elementType, MimeType mimeType) {
		return getEncodableMimeTypes().contains(mimeType);
	}

	@NonNull
	@Override
	public Flux<DataBuffer> encode(Publisher<? extends OAuth2Error> error, DataBufferFactory bufferFactory,
			ResolvableType elementType, MimeType mimeType, Map<String, Object> hints) {
		return Mono.from(error).flatMap((data) -> {
			ByteArrayHttpOutputMessage bytes = new ByteArrayHttpOutputMessage();
			try {
				this.messageConverter.write(data, MediaType.APPLICATION_JSON, bytes);
				return Mono.just(bytes.getBody().toByteArray());
			}
			catch (IOException ex) {
				return Mono.error(ex);
			}
		}).map(bufferFactory::wrap).flux();
	}

	@NonNull
	@Override
	public List<MimeType> getEncodableMimeTypes() {
		return List.of(MediaType.APPLICATION_JSON);
	}

	private static class ByteArrayHttpOutputMessage implements HttpOutputMessage {

		private final ByteArrayOutputStream body = new ByteArrayOutputStream();

		@NonNull
		@Override
		public ByteArrayOutputStream getBody() {
			return this.body;
		}

		@NonNull
		@Override
		public HttpHeaders getHeaders() {
			return new HttpHeaders();
		}

	}

}
