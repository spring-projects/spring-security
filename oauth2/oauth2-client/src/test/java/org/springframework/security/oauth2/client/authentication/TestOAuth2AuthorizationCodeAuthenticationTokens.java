/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.client.authentication;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationExchanges;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class TestOAuth2AuthorizationCodeAuthenticationTokens {

	public static OAuth2AuthorizationCodeAuthenticationToken unauthenticated() {
		ClientRegistration registration = TestClientRegistrations.clientRegistration().build();
		OAuth2AuthorizationExchange exchange = TestOAuth2AuthorizationExchanges.success();
		return new OAuth2AuthorizationCodeAuthenticationToken(registration, exchange);
	}

	public static OAuth2AuthorizationCodeAuthenticationToken authenticated() {
		ClientRegistration registration = TestClientRegistrations.clientRegistration().build();
		OAuth2AuthorizationExchange exchange = TestOAuth2AuthorizationExchanges.success();
		OAuth2AccessToken accessToken = TestOAuth2AccessTokens.noScopes();
		OAuth2RefreshToken refreshToken = TestOAuth2RefreshTokens.refreshToken();
		return new OAuth2AuthorizationCodeAuthenticationToken(registration, exchange, accessToken, refreshToken);
	}
}
