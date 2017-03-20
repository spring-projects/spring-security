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
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.TokenResponseAttributes;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * An implementation of an {@link AuthorizationGrantTokenExchanger} that <i>&quot;exchanges&quot;</i>
 * an <i>authorization code</i> credential for an <i>access token</i> credential
 * at the authorization server's <i>Token Endpoint</i>.
 *
 * <p>
 * <b>NOTE:</b> This implementation uses the <b>Nimbus OAuth 2.0 SDK</b> internally.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationCodeAuthenticationToken
 * @see TokenResponseAttributes
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-oauth-openid-connect-sdk">Nimbus OAuth 2.0 SDK</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request (Authorization Code Grant)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.4">Section 4.1.4 Access Token Response (Authorization Code Grant)</a>
 */
public class NimbusAuthorizationCodeTokenExchanger implements AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> {
	private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

	@Override
	public TokenResponseAttributes exchange(AuthorizationCodeAuthenticationToken authorizationCodeAuthenticationToken)
			throws OAuth2AuthenticationException {

		ClientRegistration clientRegistration = authorizationCodeAuthenticationToken.getClientRegistration();

		// Build the authorization code grant request for the token endpoint
		AuthorizationCode authorizationCode = new AuthorizationCode(authorizationCodeAuthenticationToken.getAuthorizationCode());
		URI redirectUri = this.toURI(clientRegistration.getRedirectUri());
		AuthorizationGrant authorizationCodeGrant = new AuthorizationCodeGrant(authorizationCode, redirectUri);
		URI tokenUri = this.toURI(clientRegistration.getProviderDetails().getTokenUri());

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
			throw new OAuth2AuthenticationException(new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE), pe);
		} catch (IOException ioe) {
			// This error occurs when there is a network-related issue
			throw new AuthenticationServiceException("An error occurred while sending the Access Token Request: " +
					ioe.getMessage(), ioe);
		}

		if (!tokenResponse.indicatesSuccess()) {
			TokenErrorResponse tokenErrorResponse = (TokenErrorResponse) tokenResponse;
			ErrorObject errorObject = tokenErrorResponse.getErrorObject();
			OAuth2Error oauth2Error = new OAuth2Error(errorObject.getCode(), errorObject.getDescription(),
				(errorObject.getURI() != null ? errorObject.getURI().toString() : null));
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		AccessTokenResponse accessTokenResponse = (AccessTokenResponse) tokenResponse;

		String accessToken = accessTokenResponse.getTokens().getAccessToken().getValue();
		AccessToken.TokenType accessTokenType = null;
		if (AccessToken.TokenType.BEARER.value().equals(accessTokenResponse.getTokens().getAccessToken().getType().getValue())) {
			accessTokenType = AccessToken.TokenType.BEARER;
		}
		long expiresIn = accessTokenResponse.getTokens().getAccessToken().getLifetime();
		Set<String> scopes = Collections.emptySet();
		if (!CollectionUtils.isEmpty(accessTokenResponse.getTokens().getAccessToken().getScope())) {
			scopes = new HashSet<>(accessTokenResponse.getTokens().getAccessToken().getScope().toStringList());
		}
		Map<String, Object> additionalParameters = accessTokenResponse.getCustomParameters().entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

		return TokenResponseAttributes.withToken(accessToken)
			.tokenType(accessTokenType)
			.expiresIn(expiresIn)
			.scopes(scopes)
			.additionalParameters(additionalParameters)
			.build();
	}

	private URI toURI(String uriStr) {
		try {
			return new URI(uriStr);
		} catch (Exception ex) {
			throw new IllegalArgumentException("An error occurred parsing URI: " + uriStr, ex);
		}
	}
}
