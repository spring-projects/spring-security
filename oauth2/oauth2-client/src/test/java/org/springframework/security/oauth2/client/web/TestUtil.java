/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.web;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Arrays;

/**
 * @author Joe Grandja
 */
class TestUtil {
	static final String DEFAULT_SCHEME = "https";
	static final String DEFAULT_SERVER_NAME = "localhost";
	static final int DEFAULT_SERVER_PORT = 8080;
	static final String DEFAULT_SERVER_URL = DEFAULT_SCHEME + "://" + DEFAULT_SERVER_NAME + ":" + DEFAULT_SERVER_PORT;
	static final String AUTHORIZATION_BASE_URI = "/oauth2/authorization";
	static final String AUTHORIZE_BASE_URI = "/login/oauth2";
	static final String GOOGLE_REGISTRATION_ID = "google";
	static final String GITHUB_REGISTRATION_ID = "github";

	static ClientRegistrationRepository clientRegistrationRepository(ClientRegistration... clientRegistrations) {
		return new InMemoryClientRegistrationRepository(Arrays.asList(clientRegistrations));
	}

	static ClientRegistration googleClientRegistration() {
		return googleClientRegistration(DEFAULT_SERVER_URL + AUTHORIZE_BASE_URI + "/" + GOOGLE_REGISTRATION_ID);
	}

	static ClientRegistration googleClientRegistration(String redirectUri) {
		return ClientRegistration.withRegistrationId(GOOGLE_REGISTRATION_ID)
			.clientId("google-client-id")
			.clientSecret("secret")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.clientName("Google Client")
			.authorizationUri("https://accounts.google.com/o/oauth2/auth")
			.tokenUri("https://accounts.google.com/o/oauth2/token")
			.userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
			.jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
			.redirectUri(redirectUri)
			.scope("openid", "email", "profile")
			.build();
	}

	static ClientRegistration githubClientRegistration() {
		return githubClientRegistration(DEFAULT_SERVER_URL + AUTHORIZE_BASE_URI + "/" + GITHUB_REGISTRATION_ID);
	}

	static ClientRegistration githubClientRegistration(String redirectUri) {
		return ClientRegistration.withRegistrationId(GITHUB_REGISTRATION_ID)
			.clientId("github-client-id")
			.clientSecret("secret")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.clientName("GitHub Client")
			.authorizationUri("https://github.com/login/oauth/authorize")
			.tokenUri("https://github.com/login/oauth/access_token")
			.userInfoUri("https://api.github.com/user")
			.redirectUri(redirectUri)
			.scope("user")
			.build();
	}
}
