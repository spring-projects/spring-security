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

import io.rsocket.metadata.WellKnownMimeType;
import org.springframework.messaging.rsocket.DefaultMetadataExtractor;
import org.springframework.messaging.rsocket.MetadataExtractor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.security.rsocket.metadata.BasicAuthenticationDecoder;
import org.springframework.security.rsocket.metadata.UsernamePasswordMetadata;
import org.springframework.util.MimeType;
import org.springframework.util.MimeTypeUtils;
import reactor.core.publisher.Mono;

/**
 * Converts from the {@link PayloadExchange} to a
 * {@link UsernamePasswordAuthenticationToken} by extracting
 * {@link UsernamePasswordMetadata#BASIC_AUTHENTICATION_MIME_TYPE} from the metadata.
 *
 * @author Rob Winch
 * @since 5.2
 */
public class BasicAuthenticationPayloadExchangeConverter implements PayloadExchangeAuthenticationConverter {

	private MimeType metadataMimetype = MimeTypeUtils.parseMimeType(
			WellKnownMimeType.MESSAGE_RSOCKET_COMPOSITE_METADATA.getString());

	private MetadataExtractor metadataExtractor = createDefaultExtractor();

	@Override
	public Mono<Authentication> convert(PayloadExchange exchange) {
		return Mono.fromCallable(() -> this.metadataExtractor
				.extract(exchange.getPayload(), this.metadataMimetype))
				.flatMap(metadata -> Mono.justOrEmpty(metadata.get(UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE.toString())))
				.cast(UsernamePasswordMetadata.class)
				.map(credentials -> new UsernamePasswordAuthenticationToken(credentials.getUsername(), credentials.getPassword()));
	}

	private static MetadataExtractor createDefaultExtractor() {
		DefaultMetadataExtractor result = new DefaultMetadataExtractor(new BasicAuthenticationDecoder());
		result.metadataToExtract(UsernamePasswordMetadata.BASIC_AUTHENTICATION_MIME_TYPE, UsernamePasswordMetadata.class, (String) null);
		return result;
	}
}
