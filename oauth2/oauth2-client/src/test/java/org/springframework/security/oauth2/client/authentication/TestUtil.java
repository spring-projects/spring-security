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
package org.springframework.security.oauth2.client.authentication;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationProperties;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
class TestUtil {
	static final String DEFAULT_SCHEME = "https";
	static final String DEFAULT_SERVER_NAME = "localhost";
	static final int DEFAULT_SERVER_PORT = 8080;
	static final String DEFAULT_SERVER_URL = DEFAULT_SCHEME + "://" + DEFAULT_SERVER_NAME + ":" + DEFAULT_SERVER_PORT;
	static final String AUTHORIZATION_BASE_URI = "/oauth2/authorization/code";
	static final String AUTHORIZE_BASE_URI = "/oauth2/authorize/code";
	static final String GOOGLE_CLIENT_ALIAS = "google";
	static final String GITHUB_CLIENT_ALIAS = "github";

	static ClientRegistrationRepository clientRegistrationRepository(ClientRegistration... clientRegistrations) {
		return new InMemoryClientRegistrationRepository(Arrays.asList(clientRegistrations));
	}

	static ClientRegistration googleClientRegistration() {
		return googleClientRegistration(DEFAULT_SERVER_URL + AUTHORIZE_BASE_URI + "/" + GOOGLE_CLIENT_ALIAS);
	}

	static ClientRegistration googleClientRegistration(String redirectUri) {
		ClientRegistrationProperties clientRegistrationProperties = new ClientRegistrationProperties();
		clientRegistrationProperties.setClientId("google-client-id");
		clientRegistrationProperties.setClientSecret("secret");
		clientRegistrationProperties.setAuthorizedGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
		clientRegistrationProperties.setClientName("Google Client");
		clientRegistrationProperties.setClientAlias(GOOGLE_CLIENT_ALIAS);
		clientRegistrationProperties.setAuthorizationUri("https://accounts.google.com/o/oauth2/auth");
		clientRegistrationProperties.setTokenUri("https://accounts.google.com/o/oauth2/token");
		clientRegistrationProperties.setUserInfoUri("https://www.googleapis.com/oauth2/v3/userinfo");
		clientRegistrationProperties.setRedirectUri(redirectUri);
		clientRegistrationProperties.setScopes(Arrays.stream(new String[] {"openid", "email", "profile"}).collect(Collectors.toSet()));
		return new ClientRegistration.Builder(clientRegistrationProperties).build();
	}

	static ClientRegistration githubClientRegistration() {
		return githubClientRegistration(DEFAULT_SERVER_URL + AUTHORIZE_BASE_URI + "/" + GITHUB_CLIENT_ALIAS);
	}

	static ClientRegistration githubClientRegistration(String redirectUri) {
		ClientRegistrationProperties clientRegistrationProperties = new ClientRegistrationProperties();
		clientRegistrationProperties.setClientId("github-client-id");
		clientRegistrationProperties.setClientSecret("secret");
		clientRegistrationProperties.setAuthorizedGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
		clientRegistrationProperties.setClientName("GitHub Client");
		clientRegistrationProperties.setClientAlias(GITHUB_CLIENT_ALIAS);
		clientRegistrationProperties.setAuthorizationUri("https://github.com/login/oauth/authorize");
		clientRegistrationProperties.setTokenUri("https://github.com/login/oauth/access_token");
		clientRegistrationProperties.setUserInfoUri("https://api.github.com/user");
		clientRegistrationProperties.setRedirectUri(redirectUri);
		clientRegistrationProperties.setScopes(Arrays.stream(new String[] {"user"}).collect(Collectors.toSet()));
		return new ClientRegistration.Builder(clientRegistrationProperties).build();
	}
}
