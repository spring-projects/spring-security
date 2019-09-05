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

package org.springframework.security.rsocket.interceptor.authentication;

import io.netty.buffer.ByteBuf;
import io.rsocket.metadata.CompositeMetadata;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.rsocket.interceptor.PayloadExchange;
import org.springframework.security.rsocket.metadata.BearerTokenMetadata;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * Converts from the {@link PayloadExchange} to a
 *  {@link BearerTokenAuthenticationToken} by extracting
 *  {@link BearerTokenMetadata#BEARER_AUTHENTICATION_MIME_TYPE} from the metadata.
 *  @author Rob Winch
 * @since 5.2
 */
public class BearerPayloadExchangeConverter implements PayloadExchangeAuthenticationConverter {

	private static final String BEARER_MIME_TYPE_VALUE =
			BearerTokenMetadata.BEARER_AUTHENTICATION_MIME_TYPE.toString();

	@Override
	public Mono<Authentication> convert(PayloadExchange exchange) {
		ByteBuf metadata = exchange.getPayload().metadata();
		CompositeMetadata compositeMetadata = new CompositeMetadata(metadata, false);
		for (CompositeMetadata.Entry entry : compositeMetadata) {
			if (BEARER_MIME_TYPE_VALUE.equals(entry.getMimeType())) {
				ByteBuf content = entry.getContent();
				String token = content.toString(StandardCharsets.UTF_8);
				return Mono.just(new BearerTokenAuthenticationToken(token));
			}
		}
		return Mono.empty();
	}
}
