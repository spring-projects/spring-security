/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.oauth2.client.jackson2;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.StdConverter;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * A {@code JsonDeserializer} for {@link OAuth2AuthorizationRequest}.
 *
 * @author Joe Grandja
 * @since 5.3
 * @see OAuth2AuthorizationRequest
 * @see OAuth2AuthorizationRequestMixin
 */
final class OAuth2AuthorizationRequestDeserializer extends JsonDeserializer<OAuth2AuthorizationRequest> {

	private static final StdConverter<JsonNode, AuthorizationGrantType> AUTHORIZATION_GRANT_TYPE_CONVERTER = new StdConverters.AuthorizationGrantTypeConverter();

	@Override
	public OAuth2AuthorizationRequest deserialize(JsonParser parser, DeserializationContext context)
			throws IOException {
		ObjectMapper mapper = (ObjectMapper) parser.getCodec();
		JsonNode authorizationRequestNode = mapper.readTree(parser);

		AuthorizationGrantType authorizationGrantType = AUTHORIZATION_GRANT_TYPE_CONVERTER
				.convert(JsonNodeUtils.findObjectNode(authorizationRequestNode, "authorizationGrantType"));

		OAuth2AuthorizationRequest.Builder builder;
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
			builder = OAuth2AuthorizationRequest.authorizationCode();
		}
		else if (AuthorizationGrantType.IMPLICIT.equals(authorizationGrantType)) {
			builder = OAuth2AuthorizationRequest.implicit();
		}
		else {
			throw new JsonParseException(parser, "Invalid authorizationGrantType");
		}

		return builder.authorizationUri(JsonNodeUtils.findStringValue(authorizationRequestNode, "authorizationUri"))
				.clientId(JsonNodeUtils.findStringValue(authorizationRequestNode, "clientId"))
				.redirectUri(JsonNodeUtils.findStringValue(authorizationRequestNode, "redirectUri"))
				.scopes(JsonNodeUtils
						.findValue(authorizationRequestNode, "scopes", JsonNodeUtils.SET_TYPE_REFERENCE, mapper))
				.state(JsonNodeUtils.findStringValue(authorizationRequestNode, "state"))
				.additionalParameters(JsonNodeUtils.findValue(authorizationRequestNode, "additionalParameters",
						JsonNodeUtils.MAP_TYPE_REFERENCE, mapper))
				.authorizationRequestUri(
						JsonNodeUtils.findStringValue(authorizationRequestNode, "authorizationRequestUri"))
				.attributes(JsonNodeUtils.findValue(authorizationRequestNode, "attributes",
						JsonNodeUtils.MAP_TYPE_REFERENCE, mapper))
				.build();
	}

}
