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
import java.util.Set;

import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.util.StdConverter;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;

/**
 * A {@code JsonDeserializer} for {@link ClientRegistration}.
 *
 * @author Sebastien Deleuze
 * @author Joe Grandja
 * @since 7.0
 * @see ClientRegistration
 * @see ClientRegistrationMixin
 */
final class ClientRegistrationDeserializer extends ValueDeserializer<ClientRegistration> {

	private static final StdConverter<JsonNode, ClientAuthenticationMethod> CLIENT_AUTHENTICATION_METHOD_CONVERTER = new StdConverters.ClientAuthenticationMethodConverter();

	private static final StdConverter<JsonNode, AuthorizationGrantType> AUTHORIZATION_GRANT_TYPE_CONVERTER = new StdConverters.AuthorizationGrantTypeConverter();

	private static final StdConverter<JsonNode, AuthenticationMethod> AUTHENTICATION_METHOD_CONVERTER = new StdConverters.AuthenticationMethodConverter();

	@Override
	public ClientRegistration deserialize(JsonParser parser, DeserializationContext context) {
		JsonNode clientRegistrationNode = context.readTree(parser);
		JsonNode providerDetailsNode = JsonNodeUtils.findObjectNode(clientRegistrationNode, "providerDetails");
		JsonNode userInfoEndpointNode = JsonNodeUtils.findObjectNode(providerDetailsNode, "userInfoEndpoint");
		String registrationId = JsonNodeUtils.findStringValue(clientRegistrationNode, "registrationId");
		Assert.hasText(registrationId, "registrationId cannot be null or empty");
		String clientId = JsonNodeUtils.findStringValue(clientRegistrationNode, "clientId");
		Assert.hasText(clientId, "clientId cannot be null or empty");
		String clientSecret = JsonNodeUtils.findStringValue(clientRegistrationNode, "clientSecret");
		String redirectUri = JsonNodeUtils.findStringValue(clientRegistrationNode, "redirectUri");
		Set<String> scopes = JsonNodeUtils.findValue(clientRegistrationNode, "scopes", JsonNodeUtils.STRING_SET,
				context);
		String clientName = JsonNodeUtils.findStringValue(clientRegistrationNode, "clientName");
		String authorizationUri = JsonNodeUtils.findStringValue(providerDetailsNode, "authorizationUri");
		String tokenUri = JsonNodeUtils.findStringValue(providerDetailsNode, "tokenUri");
		Assert.hasText(tokenUri, "tokenUri cannot be null or empty");
		String userInfoUri = JsonNodeUtils.findStringValue(userInfoEndpointNode, "uri");
		String userNameAttributeName = JsonNodeUtils.findStringValue(userInfoEndpointNode, "userNameAttributeName");
		String jwkSetUri = JsonNodeUtils.findStringValue(providerDetailsNode, "jwkSetUri");
		String issuerUri = JsonNodeUtils.findStringValue(providerDetailsNode, "issuerUri");
		Map<String, Object> configurationMetadata = JsonNodeUtils.findValue(providerDetailsNode,
				"configurationMetadata", JsonNodeUtils.STRING_OBJECT_MAP, context);
		ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId)
			.clientId(clientId)
			.clientSecret(clientSecret)
			.clientAuthenticationMethod(CLIENT_AUTHENTICATION_METHOD_CONVERTER
				.convert(JsonNodeUtils.findObjectNode(clientRegistrationNode, "clientAuthenticationMethod")))
			.authorizationGrantType(AUTHORIZATION_GRANT_TYPE_CONVERTER
				.convert(JsonNodeUtils.findObjectNode(clientRegistrationNode, "authorizationGrantType")))
			.redirectUri(redirectUri)
			.scope(scopes)
			.clientName(clientName)
			.authorizationUri(authorizationUri)
			.tokenUri(tokenUri)
			.userInfoUri(userInfoUri)
			.userInfoAuthenticationMethod(AUTHENTICATION_METHOD_CONVERTER
				.convert(JsonNodeUtils.findObjectNode(userInfoEndpointNode, "authenticationMethod")))
			.userNameAttributeName(userNameAttributeName)
			.jwkSetUri(jwkSetUri)
			.issuerUri(issuerUri)
			.providerConfigurationMetadata(
					(configurationMetadata != null) ? configurationMetadata : java.util.Collections.emptyMap());
		return builder.build();
	}

}
