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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.util.StdConverter;

import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

/**
 * {@code StdConverter} implementations.
 *
 * @author Joe Grandja
 * @since 5.3
 */
abstract class StdConverters {

	static final class AccessTokenTypeConverter extends StdConverter<JsonNode, OAuth2AccessToken.TokenType> {

		@Override
		public OAuth2AccessToken.TokenType convert(JsonNode jsonNode) {
			String value = JsonNodeUtils.findStringValue(jsonNode, "value");
			if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(value)) {
				return OAuth2AccessToken.TokenType.BEARER;
			}
			return null;
		}

	}

	static final class ClientAuthenticationMethodConverter extends StdConverter<JsonNode, ClientAuthenticationMethod> {

		@Override
		public ClientAuthenticationMethod convert(JsonNode jsonNode) {
			String value = JsonNodeUtils.findStringValue(jsonNode, "value");
			if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equalsIgnoreCase(value)
					|| ClientAuthenticationMethod.BASIC.getValue().equalsIgnoreCase(value)) {
				return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
			}
			if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equalsIgnoreCase(value)
					|| ClientAuthenticationMethod.POST.getValue().equalsIgnoreCase(value)) {
				return ClientAuthenticationMethod.CLIENT_SECRET_POST;
			}
			if (ClientAuthenticationMethod.NONE.getValue().equalsIgnoreCase(value)) {
				return ClientAuthenticationMethod.NONE;
			}
			return null;
		}

	}

	static final class AuthorizationGrantTypeConverter extends StdConverter<JsonNode, AuthorizationGrantType> {

		@Override
		public AuthorizationGrantType convert(JsonNode jsonNode) {
			String value = JsonNodeUtils.findStringValue(jsonNode, "value");
			if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equalsIgnoreCase(value)) {
				return AuthorizationGrantType.AUTHORIZATION_CODE;
			}
			if (AuthorizationGrantType.IMPLICIT.getValue().equalsIgnoreCase(value)) {
				return AuthorizationGrantType.IMPLICIT;
			}
			if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equalsIgnoreCase(value)) {
				return AuthorizationGrantType.CLIENT_CREDENTIALS;
			}
			if (AuthorizationGrantType.PASSWORD.getValue().equalsIgnoreCase(value)) {
				return AuthorizationGrantType.PASSWORD;
			}
			return null;
		}

	}

	static final class AuthenticationMethodConverter extends StdConverter<JsonNode, AuthenticationMethod> {

		@Override
		public AuthenticationMethod convert(JsonNode jsonNode) {
			String value = JsonNodeUtils.findStringValue(jsonNode, "value");
			if (AuthenticationMethod.HEADER.getValue().equalsIgnoreCase(value)) {
				return AuthenticationMethod.HEADER;
			}
			if (AuthenticationMethod.FORM.getValue().equalsIgnoreCase(value)) {
				return AuthenticationMethod.FORM;
			}
			if (AuthenticationMethod.QUERY.getValue().equalsIgnoreCase(value)) {
				return AuthenticationMethod.QUERY;
			}
			return null;
		}

	}

}
