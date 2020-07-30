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

import java.nio.charset.StandardCharsets;
import java.util.Map;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.rsocket.metadata.WellKnownMimeType;
import io.rsocket.metadata.security.AuthMetadataFlyweight;
import io.rsocket.metadata.security.WellKnownAuthType;
import reactor.core.publisher.Mono;

import org.springframework.core.codec.ByteArrayDecoder;
import org.springframework.messaging.rsocket.DefaultMetadataExtractor;
import org.springframework.messaging.rsocket.MetadataExtractor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.rsocket.api.PayloadExchange;
import org.springframework.util.MimeType;
import org.springframework.util.MimeTypeUtils;

/**
 * Converts from the {@link PayloadExchange} for <a href=
 * "https://github.com/rsocket/rsocket/blob/5920ed374d008abb712cb1fd7c9d91778b2f4a68/Extensions/Security/Authentication.md">Authentication
 * Extension</a>. For <a href=
 * "https://github.com/rsocket/rsocket/blob/5920ed374d008abb712cb1fd7c9d91778b2f4a68/Extensions/Security/Simple.md">Simple</a>
 * a {@link UsernamePasswordAuthenticationToken} is returned. For <a href=
 * "https://github.com/rsocket/rsocket/blob/5920ed374d008abb712cb1fd7c9d91778b2f4a68/Extensions/Security/Bearer.md">Bearer</a>
 * a {@link BearerTokenAuthenticationToken} is returned.
 *
 * @author Rob Winch
 * @since 5.3
 */
public class AuthenticationPayloadExchangeConverter implements PayloadExchangeAuthenticationConverter {

	private static final MimeType COMPOSITE_METADATA_MIME_TYPE = MimeTypeUtils
			.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_COMPOSITE_METADATA.getString());

	private static final MimeType AUTHENTICATION_MIME_TYPE = MimeTypeUtils
			.parseMimeType(WellKnownMimeType.MESSAGE_RSOCKET_AUTHENTICATION.getString());

	private MetadataExtractor metadataExtractor = createDefaultExtractor();

	@Override
	public Mono<Authentication> convert(PayloadExchange exchange) {
		return Mono
				.fromCallable(() -> this.metadataExtractor.extract(exchange.getPayload(),
						AuthenticationPayloadExchangeConverter.COMPOSITE_METADATA_MIME_TYPE))
				.flatMap((metadata) -> Mono.justOrEmpty(authentication(metadata)));
	}

	private Authentication authentication(Map<String, Object> metadata) {
		byte[] authenticationMetadata = (byte[]) metadata.get("authentication");
		if (authenticationMetadata == null) {
			return null;
		}
		ByteBuf rawAuthentication = ByteBufAllocator.DEFAULT.buffer().writeBytes(authenticationMetadata);
		if (!AuthMetadataFlyweight.isWellKnownAuthType(rawAuthentication)) {
			return null;
		}
		WellKnownAuthType wellKnownAuthType = AuthMetadataFlyweight.decodeWellKnownAuthType(rawAuthentication);
		if (WellKnownAuthType.SIMPLE.equals(wellKnownAuthType)) {
			return simple(rawAuthentication);
		}
		else if (WellKnownAuthType.BEARER.equals(wellKnownAuthType)) {
			return bearer(rawAuthentication);
		}
		throw new IllegalArgumentException("Unknown Mime Type " + wellKnownAuthType);
	}

	private Authentication simple(ByteBuf rawAuthentication) {
		ByteBuf rawUsername = AuthMetadataFlyweight.decodeUsername(rawAuthentication);
		String username = rawUsername.toString(StandardCharsets.UTF_8);
		ByteBuf rawPassword = AuthMetadataFlyweight.decodePassword(rawAuthentication);
		String password = rawPassword.toString(StandardCharsets.UTF_8);
		return new UsernamePasswordAuthenticationToken(username, password);
	}

	private Authentication bearer(ByteBuf rawAuthentication) {
		char[] rawToken = AuthMetadataFlyweight.decodeBearerTokenAsCharArray(rawAuthentication);
		String token = new String(rawToken);
		return new BearerTokenAuthenticationToken(token);
	}

	private static MetadataExtractor createDefaultExtractor() {
		DefaultMetadataExtractor result = new DefaultMetadataExtractor(new ByteArrayDecoder());
		result.metadataToExtract(AUTHENTICATION_MIME_TYPE, byte[].class, "authentication");
		return result;
	}

}
