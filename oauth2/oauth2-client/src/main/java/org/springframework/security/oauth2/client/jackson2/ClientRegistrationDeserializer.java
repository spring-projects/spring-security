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

import java.io.IOException;

import static org.springframework.security.oauth2.client.jackson2.JsonNodeUtils.MAP_TYPE_REFERENCE;
import static org.springframework.security.oauth2.client.jackson2.JsonNodeUtils.SET_TYPE_REFERENCE;
import static org.springframework.security.oauth2.client.jackson2.JsonNodeUtils.findObjectNode;
import static org.springframework.security.oauth2.client.jackson2.JsonNodeUtils.findStringValue;
import static org.springframework.security.oauth2.client.jackson2.JsonNodeUtils.findValue;

/**
 * A {@code JsonDeserializer} for {@link ClientRegistration}.
 *
 * @author Joe Grandja
 * @since 5.3
 * @see ClientRegistration
 * @see ClientRegistrationMixin
 */
final class ClientRegistrationDeserializer extends JsonDeserializer<ClientRegistration> {
	private static final StdConverter<JsonNode, ClientAuthenticationMethod> CLIENT_AUTHENTICATION_METHOD_CONVERTER =
			new StdConverters.ClientAuthenticationMethodConverter();
	private static final StdConverter<JsonNode, AuthorizationGrantType> AUTHORIZATION_GRANT_TYPE_CONVERTER =
			new StdConverters.AuthorizationGrantTypeConverter();
	private static final StdConverter<JsonNode, AuthenticationMethod> AUTHENTICATION_METHOD_CONVERTER =
			new StdConverters.AuthenticationMethodConverter();

	@Override
	public ClientRegistration deserialize(JsonParser parser, DeserializationContext context) throws IOException {
		ObjectMapper mapper = (ObjectMapper) parser.getCodec();
		JsonNode clientRegistrationNode = mapper.readTree(parser);
		JsonNode providerDetailsNode = findObjectNode(clientRegistrationNode, "providerDetails");
		JsonNode userInfoEndpointNode = findObjectNode(providerDetailsNode, "userInfoEndpoint");

		return ClientRegistration
				.withRegistrationId(findStringValue(clientRegistrationNode, "registrationId"))
				.clientId(findStringValue(clientRegistrationNode, "clientId"))
				.clientSecret(findStringValue(clientRegistrationNode, "clientSecret"))
				.clientAuthenticationMethod(
						CLIENT_AUTHENTICATION_METHOD_CONVERTER.convert(
								findObjectNode(clientRegistrationNode, "clientAuthenticationMethod")))
				.authorizationGrantType(
						AUTHORIZATION_GRANT_TYPE_CONVERTER.convert(
								findObjectNode(clientRegistrationNode, "authorizationGrantType")))
				.redirectUri(findStringValue(clientRegistrationNode, "redirectUri"))
				.scope(findValue(clientRegistrationNode, "scopes", SET_TYPE_REFERENCE, mapper))
				.clientName(findStringValue(clientRegistrationNode, "clientName"))
				.authorizationUri(findStringValue(providerDetailsNode, "authorizationUri"))
				.tokenUri(findStringValue(providerDetailsNode, "tokenUri"))
				.userInfoUri(findStringValue(userInfoEndpointNode, "uri"))
				.userInfoAuthenticationMethod(
						AUTHENTICATION_METHOD_CONVERTER.convert(
								findObjectNode(userInfoEndpointNode, "authenticationMethod")))
				.userNameAttributeName(findStringValue(userInfoEndpointNode, "userNameAttributeName"))
				.jwkSetUri(findStringValue(providerDetailsNode, "jwkSetUri"))
				.issuerUri(findStringValue(providerDetailsNode, "issuerUri"))
				.providerConfigurationMetadata(findValue(providerDetailsNode, "configurationMetadata", MAP_TYPE_REFERENCE, mapper))
				.build();
	}
}
