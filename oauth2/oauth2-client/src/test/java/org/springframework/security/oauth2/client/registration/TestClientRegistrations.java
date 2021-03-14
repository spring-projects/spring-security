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

package org.springframework.security.oauth2.client.registration;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * @author Rob Winch
 * @since 5.1
 */
public final class TestClientRegistrations {

	private TestClientRegistrations() {
	}

	public static ClientRegistration.Builder clientRegistration() {
		// @formatter:off
		return ClientRegistration.withRegistrationId("registration-id")
				.redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.scope("read:user")
				.authorizationUri("https://example.com/login/oauth/authorize")
				.tokenUri("https://example.com/login/oauth/access_token")
				.jwkSetUri("https://example.com/oauth2/jwk")
				.issuerUri("https://example.com")
				.userInfoUri("https://api.example.com/user")
				.userNameAttributeName("id")
				.clientName("Client Name")
				.clientId("client-id")
				.clientSecret("client-secret");
		// @formatter:on
	}

	public static ClientRegistration.Builder clientRegistration2() {
		// @formatter:off
		return ClientRegistration.withRegistrationId("registration-id-2")
				.redirectUri("{baseUrl}/{action}/oauth2/code/{registrationId}")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.scope("read:user")
				.authorizationUri("https://example.com/login/oauth/authorize")
				.tokenUri("https://example.com/login/oauth/access_token")
				.userInfoUri("https://api.example.com/user")
				.userNameAttributeName("id")
				.clientName("Client Name")
				.clientId("client-id-2")
				.clientSecret("client-secret");
		// @formatter:on
	}

	public static ClientRegistration.Builder clientCredentials() {
		// @formatter:off
		return clientRegistration()
				.registrationId("client-credentials")
				.clientId("client-id")
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
		// @formatter:on
	}

	public static ClientRegistration.Builder password() {
		// @formatter:off
		return ClientRegistration.withRegistrationId("password")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.PASSWORD)
				.scope("read", "write")
				.tokenUri("https://example.com/login/oauth/access_token")
				.clientName("Client Name")
				.clientId("client-id")
				.clientSecret("client-secret");
		// @formatter:on
	}

	public static ClientRegistration.Builder jwtBearer() {
		// @formatter:off
		return ClientRegistration.withRegistrationId("jwt-bearer")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
				.scope("read", "write")
				.tokenUri("https://example.com/login/oauth/access_token")
				.clientName("Client Name")
				.clientId("client-id")
				.clientSecret("client-secret");
		// @formatter:on
	}

}
