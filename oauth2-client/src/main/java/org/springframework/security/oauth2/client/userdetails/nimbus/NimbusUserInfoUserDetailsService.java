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
package org.springframework.security.oauth2.client.userdetails.nimbus;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userdetails.UserInfoUserDetailsService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.userdetails.OAuth2UserBuilder;
import org.springframework.security.oauth2.core.userdetails.OAuth2UserDetails;
import org.springframework.security.openid.connect.core.userdetails.OpenIDConnectUserBuilder;
import org.springframework.util.Assert;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Joe Grandja
 */
public class NimbusUserInfoUserDetailsService implements UserInfoUserDetailsService {

	private final HttpMessageConverter jacksonHttpMessageConverter = new MappingJackson2HttpMessageConverter();

	private final Map<URI, Class<? extends OAuth2UserDetails>> userInfoTypeMapping = new HashMap<>();


	@Override
	public UserDetails loadUserDetails(OAuth2AuthenticationToken authenticationToken) throws OAuth2AuthenticationException {
		OAuth2UserDetails oauth2User = null;

		try {
			ClientRegistration clientRegistration = authenticationToken.getClientRegistration();

			URI userInfoUri = clientRegistration.getProviderDetails().getUserInfoUri();
			BearerAccessToken accessToken = new BearerAccessToken(authenticationToken.getAccessToken().getValue());

			// Request the User Info
			UserInfoRequest userInfoRequest = new UserInfoRequest(userInfoUri, accessToken);
			HTTPRequest httpRequest = userInfoRequest.toHTTPRequest();
			httpRequest.setAccept(MediaType.APPLICATION_JSON_VALUE);
			HTTPResponse httpResponse = httpRequest.send();

			if (httpResponse.getStatusCode() != HTTPResponse.SC_OK) {
				UserInfoErrorResponse userInfoErrorResponse = UserInfoErrorResponse.parse(httpResponse);
				ErrorObject errorObject = userInfoErrorResponse.getErrorObject();
				OAuth2Error oauth2Error = OAuth2Error.valueOf(
						errorObject.getCode(), errorObject.getDescription(), errorObject.getURI());
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.getErrorMessage());
			}

			ClientHttpResponse clientHttpResponse = new NimbusClientHttpResponse(httpResponse);

			if (this.isUserInfoTypeMapped(clientRegistration)) {
				oauth2User = this.readCustomUserInfoType(clientHttpResponse, clientRegistration);
			}
			if (oauth2User == null) {
				oauth2User = this.readDefaultUserInfoType(clientHttpResponse, clientRegistration);
			}

		} catch (ParseException | HttpMessageNotReadableException ex) {
			// This error occurs if the User Info Response is not well-formed or
			// invalid or if the supplied custom type for the userInfo object
			// failed to deserialize for some reason
			throw new OAuth2AuthenticationException(OAuth2Error.invalidUserInfoResponse(), ex);
		} catch (IOException ex) {
			// This error occurs when there is a network-related issue
			throw new AuthenticationServiceException("An error occurred while sending the User Info Request: " +
					ex.getMessage(), ex);
		}

		return oauth2User;
	}

	@Override
	public final void mapUserInfoType(Class<? extends OAuth2UserDetails> userInfoType, URI userInfoUri) {
		Assert.notNull(userInfoType, "userInfoType cannot be null");
		Assert.notNull(userInfoUri, "userInfoUri cannot be null");
		this.userInfoTypeMapping.put(userInfoUri, userInfoType);
	}

	private Class<? extends OAuth2UserDetails> getUserInfoType(ClientRegistration clientRegistration) {
		return this.userInfoTypeMapping.get(clientRegistration.getProviderDetails().getUserInfoUri());
	}

	private boolean isUserInfoTypeMapped(ClientRegistration clientRegistration) {
		return this.getUserInfoType(clientRegistration) != null;
	}

	private OAuth2UserDetails readCustomUserInfoType(ClientHttpResponse clientHttpResponse, ClientRegistration clientRegistration) {
		OAuth2UserDetails oauth2User = null;

		Class<? extends OAuth2UserDetails> userInfoType = this.getUserInfoType(clientRegistration);

		if (this.jacksonHttpMessageConverter.canRead(userInfoType, null)) {
			try {
				oauth2User = (OAuth2UserDetails) this.jacksonHttpMessageConverter.read(userInfoType, clientHttpResponse);
			} catch (IOException ex) {
				// IOException will never occur here as the response has been fully read
				// by HTTPResponse (Nimbus). Default the return to null.
			}
		}

		return oauth2User;
	}

	private OAuth2UserDetails readDefaultUserInfoType(ClientHttpResponse clientHttpResponse, ClientRegistration clientRegistration) {
		OAuth2UserDetails oauth2User = null;

		try {
			Map<String, Object> userAttributes = (Map<String, Object>) this.jacksonHttpMessageConverter.read(Map.class, clientHttpResponse);
			if (clientRegistration.getProviderDetails().isOpenIdProvider()) {
				oauth2User = new OpenIDConnectUserBuilder().userAttributes(userAttributes).build();
			} else {
				oauth2User = new OAuth2UserBuilder().userAttributes(userAttributes).build();
			}
		} catch (IOException ex) {
			// IOException will never occur here as the response has been fully read
			// by HTTPResponse (Nimbus). Default the return to null.
		}

		return oauth2User;
	}
}