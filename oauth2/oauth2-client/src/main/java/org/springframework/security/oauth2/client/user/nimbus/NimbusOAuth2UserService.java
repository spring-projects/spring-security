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
package org.springframework.security.oauth2.client.user.nimbus;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.user.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.oidc.user.UserInfo;
import org.springframework.util.Assert;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * An implementation of an {@link OAuth2UserService} that uses the <b>Nimbus OAuth 2.0 SDK</b> internally.
 *
 * <p>
 * This implementation uses a <code>Map</code> of converter's <i>keyed</i> by <code>URI</code>.
 * The <code>URI</code> represents the <i>UserInfo Endpoint</i> address and the mapped <code>Function</code>
 * is capable of converting the <i>UserInfo Response</i> to either an
 * {@link OAuth2User} (for a standard <i>OAuth 2.0 Provider</i>) or
 * {@link UserInfo} (for an <i>OpenID Connect 1.0 Provider</i>).
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2AuthenticationToken
 * @see AuthenticatedPrincipal
 * @see OAuth2User
 * @see UserInfo
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-oauth-openid-connect-sdk">Nimbus OAuth 2.0 SDK</a>
 */
public class NimbusOAuth2UserService implements OAuth2UserService {
	private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";
	private final Map<URI, Function<ClientHttpResponse, ? extends OAuth2User>> userInfoTypeConverters;

	public NimbusOAuth2UserService(Map<URI, Function<ClientHttpResponse, ? extends OAuth2User>> userInfoTypeConverters) {
		Assert.notEmpty(userInfoTypeConverters, "userInfoTypeConverters cannot be empty");
		this.userInfoTypeConverters = new HashMap<>(userInfoTypeConverters);
	}

	@Override
	public OAuth2User loadUser(OAuth2AuthenticationToken token) throws OAuth2AuthenticationException {
		OAuth2User user;

		try {
			ClientRegistration clientRegistration = token.getClientRegistration();

			URI userInfoUri;
			try {
				userInfoUri = new URI(clientRegistration.getProviderDetails().getUserInfoUri());
			} catch (Exception ex) {
				throw new IllegalArgumentException("An error occurred parsing the userInfo URI: " +
					clientRegistration.getProviderDetails().getUserInfoUri(), ex);
			}

			Function<ClientHttpResponse, ? extends OAuth2User> userInfoConverter = this.userInfoTypeConverters.get(userInfoUri);
			if (userInfoConverter == null) {
				throw new IllegalArgumentException("There is no available User Info converter for " + userInfoUri.toString());
			}

			BearerAccessToken accessToken = new BearerAccessToken(token.getAccessToken().getTokenValue());

			// Request the User Info
			UserInfoRequest userInfoRequest = new UserInfoRequest(userInfoUri, accessToken);
			HTTPRequest httpRequest = userInfoRequest.toHTTPRequest();
			httpRequest.setAccept(MediaType.APPLICATION_JSON_VALUE);
			HTTPResponse httpResponse = httpRequest.send();

			if (httpResponse.getStatusCode() != HTTPResponse.SC_OK) {
				UserInfoErrorResponse userInfoErrorResponse = UserInfoErrorResponse.parse(httpResponse);
				ErrorObject errorObject = userInfoErrorResponse.getErrorObject();

				StringBuilder errorDescription = new StringBuilder();
				errorDescription.append("An error occurred while attempting to access the UserInfo Endpoint -> ");
				errorDescription.append("Error details: [");
				errorDescription.append("UserInfo Uri: ").append(userInfoUri.toString());
				errorDescription.append(", Http Status: ").append(errorObject.getHTTPStatusCode());
				if (errorObject.getCode() != null) {
					errorDescription.append(", Error Code: ").append(errorObject.getCode());
				}
				if (errorObject.getDescription() != null) {
					errorDescription.append(", Error Description: ").append(errorObject.getDescription());
				}
				errorDescription.append("]");

				OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE, errorDescription.toString(), null);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}

			user = userInfoConverter.apply(new NimbusClientHttpResponse(httpResponse));

		} catch (ParseException ex) {
			// This error occurs if the User Info Response is not well-formed or invalid
			throw new OAuth2AuthenticationException(new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE), ex);
		} catch (IOException ex) {
			// This error occurs when there is a network-related issue
			throw new AuthenticationServiceException("An error occurred while sending the User Info Request: " +
				ex.getMessage(), ex);
		}

		return user;
	}
}
