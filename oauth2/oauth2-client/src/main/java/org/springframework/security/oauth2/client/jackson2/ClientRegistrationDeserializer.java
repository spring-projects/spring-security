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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.StdConverter;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * A {@code JsonDeserializer} for {@link ClientRegistration}.
 *
 * @author Joe Grandja
 * @since 5.3
 * @see ClientRegistration
 * @see ClientRegistrationMixin
 */
final class ClientRegistrationDeserializer extends JsonDeserializer<ClientRegistration> {

	private static final StdConverter<JsonNode, ClientAuthenticationMethod> CLIENT_AUTHENTICATION_METHOD_CONVERTER = new StdConverters.ClientAuthenticationMethodConverter();

	private static final StdConverter<JsonNode, AuthorizationGrantType> AUTHORIZATION_GRANT_TYPE_CONVERTER = new StdConverters.AuthorizationGrantTypeConverter();

	private static final StdConverter<JsonNode, AuthenticationMethod> AUTHENTICATION_METHOD_CONVERTER = new StdConverters.AuthenticationMethodConverter();

	@Override
	public ClientRegistration deserialize(JsonParser parser, DeserializationContext context) throws IOException {
		ObjectMapper mapper = (ObjectMapper) parser.getCodec();
		JsonNode clientRegistrationNode = mapper.readTree(parser);
		JsonNode providerDetailsNode = JsonNodeUtils.findObjectNode(clientRegistrationNode, "providerDetails");
		JsonNode userInfoEndpointNode = JsonNodeUtils.findObjectNode(providerDetailsNode, "userInfoEndpoint");

		return ClientRegistration
				.withRegistrationId(JsonNodeUtils.findStringValue(clientRegistrationNode, "registrationId"))
				.clientId(JsonNodeUtils.findStringValue(clientRegistrationNode, "clientId"))
				.clientSecret(JsonNodeUtils.findStringValue(clientRegistrationNode, "clientSecret"))
				.clientAuthenticationMethod(CLIENT_AUTHENTICATION_METHOD_CONVERTER
						.convert(JsonNodeUtils.findObjectNode(clientRegistrationNode, "clientAuthenticationMethod")))
				.authorizationGrantType(AUTHORIZATION_GRANT_TYPE_CONVERTER
						.convert(JsonNodeUtils.findObjectNode(clientRegistrationNode, "authorizationGrantType")))
				.redirectUri(JsonNodeUtils.findStringValue(clientRegistrationNode, "redirectUri"))
				.scope(JsonNodeUtils.findValue(clientRegistrationNode, "scopes", JsonNodeUtils.SET_TYPE_REFERENCE,
						mapper))
				.clientName(JsonNodeUtils.findStringValue(clientRegistrationNode, "clientName"))
				.authorizationUri(JsonNodeUtils.findStringValue(providerDetailsNode, "authorizationUri"))
				.tokenUri(JsonNodeUtils.findStringValue(providerDetailsNode, "tokenUri"))
				.userInfoUri(JsonNodeUtils.findStringValue(userInfoEndpointNode, "uri"))
				.userInfoAuthenticationMethod(AUTHENTICATION_METHOD_CONVERTER
						.convert(JsonNodeUtils.findObjectNode(userInfoEndpointNode, "authenticationMethod")))
				.userNameAttributeName(JsonNodeUtils.findStringValue(userInfoEndpointNode, "userNameAttributeName"))
				.jwkSetUri(JsonNodeUtils.findStringValue(providerDetailsNode, "jwkSetUri"))
				.issuerUri(JsonNodeUtils.findStringValue(providerDetailsNode, "issuerUri"))
				.providerConfigurationMetadata(JsonNodeUtils.findValue(providerDetailsNode, "configurationMetadata",
						JsonNodeUtils.MAP_TYPE_REFERENCE, mapper))
				.build();
	}

}
