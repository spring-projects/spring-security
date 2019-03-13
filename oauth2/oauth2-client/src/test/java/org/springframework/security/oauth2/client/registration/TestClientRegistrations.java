/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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
public class TestClientRegistrations {
	public static ClientRegistration.Builder clientRegistration() {
		return ClientRegistration.withRegistrationId("registration-id")
			.redirectUriTemplate("{baseUrl}/{action}/oauth2/code/{registrationId}")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.scope("read:user")
			.authorizationUri("https://example.com/login/oauth/authorize")
			.tokenUri("https://example.com/login/oauth/access_token")
			.jwkSetUri("https://example.com/oauth2/jwk")
			.userInfoUri("https://api.example.com/user")
			.userNameAttributeName("id")
			.clientName("Client Name")
			.clientId("client-id")
			.clientSecret("client-secret");
	}

	public static ClientRegistration.Builder clientRegistration2() {
		return ClientRegistration.withRegistrationId("registration-id-2")
				.redirectUriTemplate("{baseUrl}/{action}/oauth2/code/{registrationId}")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.scope("read:user")
				.authorizationUri("https://example.com/login/oauth/authorize")
				.tokenUri("https://example.com/login/oauth/access_token")
				.userInfoUri("https://api.example.com/user")
				.userNameAttributeName("id")
				.clientName("Client Name")
				.clientId("client-id-2")
				.clientSecret("client-secret");
	}

	public static ClientRegistration.Builder clientRegistration3() {
		return ClientRegistration.withRegistrationId("registration-id-3")
				.redirectUriTemplate("{baseUrl}/{action}/oauth2/code/{registrationId}")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.scope("read:user")
				.authorizationUri("{baseUrl}/login/oauth/authorize")
				.tokenUri("https://example.com/login/oauth/access_token")
				.userInfoUri("https://api.example.com/user")
				.userNameAttributeName("id")
				.clientName("Client Name")
				.clientId("client-id-3")
				.clientSecret("client-secret");
	}

	public static ClientRegistration.Builder clientCredentials() {
		return clientRegistration()
				.registrationId("client-credentials")
				.clientId("client-id")
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
	}
}
