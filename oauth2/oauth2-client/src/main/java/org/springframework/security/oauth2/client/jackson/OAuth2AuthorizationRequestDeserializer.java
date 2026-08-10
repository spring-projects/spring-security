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

package org.springframework.security.oauth2.client.jackson;

import java.util.Map;

import tools.jackson.core.JsonParser;
import tools.jackson.core.exc.StreamReadException;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.util.StdConverter;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder;
import org.springframework.util.Assert;

/**
 * A {@code JsonDeserializer} for {@link OAuth2AuthorizationRequest}.
 *
 * @author Sebastien Deleuze
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2AuthorizationRequest
 * @see OAuth2AuthorizationRequestMixin
 */
final class OAuth2AuthorizationRequestDeserializer extends ValueDeserializer<OAuth2AuthorizationRequest> {

	private static final StdConverter<JsonNode, AuthorizationGrantType> AUTHORIZATION_GRANT_TYPE_CONVERTER = new StdConverters.AuthorizationGrantTypeConverter();

	@Override
	public OAuth2AuthorizationRequest deserialize(JsonParser parser, DeserializationContext context) {
		JsonNode root = context.readTree(parser);
		return deserialize(parser, context, root);
	}

	private OAuth2AuthorizationRequest deserialize(JsonParser parser, DeserializationContext context, JsonNode root) {
		AuthorizationGrantType authorizationGrantType = AUTHORIZATION_GRANT_TYPE_CONVERTER
			.convert(JsonNodeUtils.findObjectNode(root, "authorizationGrantType"));
		Builder builder = getBuilder(parser, authorizationGrantType);
		String authorizationUri = JsonNodeUtils.findStringValue(root, "authorizationUri");
		Assert.hasText(authorizationUri, "authorizationUri cannot be null or empty");
		builder.authorizationUri(authorizationUri);
		String clientId = JsonNodeUtils.findStringValue(root, "clientId");
		Assert.hasText(clientId, "clientId cannot be null or empty");
		builder.clientId(clientId);
		builder.redirectUri(JsonNodeUtils.findStringValue(root, "redirectUri"));
		builder.scopes(JsonNodeUtils.findValue(root, "scopes", JsonNodeUtils.STRING_SET, context));
		builder.state(JsonNodeUtils.findStringValue(root, "state"));
		Map<String, Object> additionalParameters = JsonNodeUtils.findValue(root, "additionalParameters",
				JsonNodeUtils.STRING_OBJECT_MAP, context);
		builder.additionalParameters(
				(additionalParameters != null) ? additionalParameters : java.util.Collections.emptyMap());
		String authorizationRequestUri = JsonNodeUtils.findStringValue(root, "authorizationRequestUri");
		Assert.hasText(authorizationRequestUri, "authorizationRequestUri cannot be null or empty");
		builder.authorizationRequestUri(authorizationRequestUri);
		Map<String, Object> attributes = JsonNodeUtils.findValue(root, "attributes", JsonNodeUtils.STRING_OBJECT_MAP,
				context);
		builder.attributes((attributes != null) ? attributes : java.util.Collections.emptyMap());
		return builder.build();
	}

	private Builder getBuilder(JsonParser parser, AuthorizationGrantType authorizationGrantType) {
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
			return OAuth2AuthorizationRequest.authorizationCode();
		}
		throw new StreamReadException(parser, "Invalid authorizationGrantType");
	}

}
