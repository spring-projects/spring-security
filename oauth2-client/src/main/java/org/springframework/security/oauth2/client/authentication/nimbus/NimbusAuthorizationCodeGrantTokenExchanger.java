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
package org.springframework.security.oauth2.client.authentication.nimbus;


import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeGrantAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.protocol.TokenResponseAttributes;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
public class NimbusAuthorizationCodeGrantTokenExchanger implements AuthorizationGrantTokenExchanger<AuthorizationCodeGrantAuthenticationToken> {

	@Override
	public TokenResponseAttributes exchange(AuthorizationCodeGrantAuthenticationToken authorizationGrantAuthentication)
			throws OAuth2AuthenticationException {

		ClientRegistration clientRegistration = authorizationGrantAuthentication.getClientRegistration();

		// Build the authorization code grant request for the token endpoint
		AuthorizationCode authorizationCode = new AuthorizationCode(authorizationGrantAuthentication.getAuthorizationCode());
		URI redirectUri = clientRegistration.getRedirectUri();
		AuthorizationGrant authorizationCodeGrant = new AuthorizationCodeGrant(authorizationCode, redirectUri);
		URI tokenUri = clientRegistration.getProviderDetails().getTokenUri();

		// Set the credentials to authenticate the client at the token endpoint
		ClientID clientId = new ClientID(clientRegistration.getClientId());
		Secret clientSecret = new Secret(clientRegistration.getClientSecret());
		ClientAuthentication clientAuthentication;
		if (ClientAuthenticationMethod.FORM.equals(clientRegistration.getClientAuthenticationMethod())) {
			clientAuthentication = new ClientSecretPost(clientId, clientSecret);
		} else {
			clientAuthentication = new ClientSecretBasic(clientId, clientSecret);
		}

		TokenResponse tokenResponse;
		try {
			// Send the Access Token request
			TokenRequest tokenRequest = new TokenRequest(tokenUri, clientAuthentication, authorizationCodeGrant);
			HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
			httpRequest.setAccept(MediaType.APPLICATION_JSON_VALUE);
			tokenResponse = TokenResponse.parse(httpRequest.send());
		} catch (ParseException pe) {
			// This error occurs if the Access Token Response is not well-formed,
			// for example, a required attribute is missing
			throw new OAuth2AuthenticationException(OAuth2Error.invalidTokenResponse(), pe);
		} catch (IOException ioe) {
			// This error occurs when there is a network-related issue
			throw new AuthenticationServiceException("An error occurred while sending the Access Token Request: " +
					ioe.getMessage(), ioe);
		}

		if (!tokenResponse.indicatesSuccess()) {
			TokenErrorResponse tokenErrorResponse = (TokenErrorResponse) tokenResponse;
			ErrorObject errorObject = tokenErrorResponse.getErrorObject();
			OAuth2Error oauth2Error = OAuth2Error.valueOf(
					errorObject.getCode(), errorObject.getDescription(), errorObject.getURI());
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.getErrorMessage());
		}

		AccessTokenResponse accessTokenResponse = (AccessTokenResponse) tokenResponse;

		String accessToken = accessTokenResponse.getTokens().getAccessToken().getValue();
		AccessToken.TokenType accessTokenType = null;
		if (AccessToken.TokenType.BEARER.value().equals(accessTokenResponse.getTokens().getAccessToken().getType().getValue())) {
			accessTokenType = AccessToken.TokenType.BEARER;
		} else if (AccessToken.TokenType.MAC.value().equals(accessTokenResponse.getTokens().getAccessToken().getType().getValue())) {
			accessTokenType = AccessToken.TokenType.MAC;
		}
		long expiresIn = accessTokenResponse.getTokens().getAccessToken().getLifetime();
		Set<String> scopes = Collections.emptySet();
		if (!CollectionUtils.isEmpty(accessTokenResponse.getTokens().getAccessToken().getScope())) {
			scopes = new HashSet<>(accessTokenResponse.getTokens().getAccessToken().getScope().toStringList());
		}
		String refreshToken = null;
		if (accessTokenResponse.getTokens().getRefreshToken() != null) {
			refreshToken = accessTokenResponse.getTokens().getRefreshToken().getValue();
		}
		Map<String, String> additionalParameters = accessTokenResponse.getCustomParameters().entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().toString()));

		return new TokenResponseAttributes(accessToken, accessTokenType, expiresIn,
				scopes, refreshToken, additionalParameters);
	}
}