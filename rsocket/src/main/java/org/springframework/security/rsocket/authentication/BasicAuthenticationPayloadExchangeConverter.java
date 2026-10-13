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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import io.rsocket.metadata.WellKnownMimeType;
import org.jspecify.annotations.Nullable;
import reactor.core.publisher.Mono;

import org.springframework.core.codec.ByteArrayDecoder;
import org.springframework.core.codec.DecodingException;
import org.springframework.http.MediaType;
import org.springframework.messaging.rsocket.DefaultMetadataExtractor;
import org.springframework.messaging.rsocket.MetadataExtractor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.util.MimeType;
import org.springframework.util.MimeTypeUtils;

/**
 * Converts from a {@link PayloadExchange} that contains
 * {@code message/x.rsocket.authentication.basic.v0} metadata to a
 * {@link UsernamePasswordAuthenticationToken}.
 *
 * <p>
 * The metadata is encoded as
 * {@code ${username-bytes-length}${username-bytes}${password-bytes}} where
 * {@code username-bytes-length} is a 4-byte big-endian integer. See
 * <a href="https://github.com/rsocket/rsocket/issues/272">rsocket/rsocket#272</a>.
 *
 * @author Rob Winch
 * @since 5.2
 * @deprecated please use {@link AuthenticationPayloadExchangeConverter} instead
 */
@Deprecated
public class BasicAuthenticationPayloadExchangeConverter implements PayloadExchangeAuthenticationConverter {

	private static final MimeType COMPOSITE_METADATA_MIME_TYPE = MimeTypeUtils
		.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_COMPOSITE_METADATA.getString());

	private static final MimeType BASIC_AUTHENTICATION_MIME_TYPE = new MediaType("message",
			"x.rsocket.authentication.basic.v0");

	private final MetadataExtractor metadataExtractor = createDefaultExtractor();

	@Override
	public Mono<Authentication> convert(PayloadExchange exchange) {
		return Mono
			.fromCallable(() -> this.metadataExtractor.extract(exchange.getPayload(),
					BasicAuthenticationPayloadExchangeConverter.COMPOSITE_METADATA_MIME_TYPE))
			.flatMap((metadata) -> Mono.justOrEmpty(authentication(metadata)));
	}

	private @Nullable Authentication authentication(Map<String, Object> metadata) {
		byte[] basicAuthenticationMetadata = (byte[]) metadata.get("basicAuthentication");
		if (basicAuthenticationMetadata == null) {
			return null;
		}
		return basicAuthentication(basicAuthenticationMetadata);
	}

	private Authentication basicAuthentication(byte[] raw) {
		ByteBuffer byteBuffer = ByteBuffer.wrap(raw);
		int usernameSize = byteBuffer.getInt();
		if (usernameSize < 0 || usernameSize > byteBuffer.remaining()) {
			throw new DecodingException("Invalid username length");
		}
		byte[] usernameBytes = new byte[usernameSize];
		byteBuffer.get(usernameBytes);
		byte[] passwordBytes = new byte[byteBuffer.remaining()];
		byteBuffer.get(passwordBytes);
		String username = new String(usernameBytes, StandardCharsets.UTF_8);
		String password = new String(passwordBytes, StandardCharsets.UTF_8);
		return UsernamePasswordAuthenticationToken.unauthenticated(username, password);
	}

	private static MetadataExtractor createDefaultExtractor() {
		DefaultMetadataExtractor result = new DefaultMetadataExtractor(new ByteArrayDecoder());
		result.metadataToExtract(BASIC_AUTHENTICATION_MIME_TYPE, byte[].class, "basicAuthentication");
		return result;
	}

}
