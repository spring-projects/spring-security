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
import org.springframework.beans.BeanWrapper;
import org.springframework.beans.PropertyAccessorFactory;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.http.HttpClientConfig;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.user.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.oidc.core.UserInfo;
import org.springframework.security.oauth2.oidc.core.user.DefaultOidcUser;
import org.springframework.security.oauth2.oidc.core.user.OidcUser;
import org.springframework.security.oauth2.oidc.core.user.OidcUserAuthority;
import org.springframework.util.Assert;

import java.io.IOException;
import java.net.URI;
import java.util.*;

/**
 * An implementation of an {@link OAuth2UserService} that uses the <b>Nimbus OAuth 2.0 SDK</b> internally.
 *
 * <p>
 * This implementation may be configured with a <code>Map</code> of custom {@link OAuth2User} types
 * <i>keyed</i> by <code>URI</code>, which represents the <i>UserInfo Endpoint</i> address.
 *
 * <p>
 * For {@link OAuth2User}'s registered at a standard <i>OAuth 2.0 Provider</i>, the attribute name
 * for the &quot;user's name&quot; is required. This can be supplied via {@link #setUserNameAttributeNames(Map)},
 * <i>keyed</i> by <code>URI</code>, which represents the <i>UserInfo Endpoint</i> address.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2AuthenticationToken
 * @see OAuth2User
 * @see OidcUser
 * @see UserInfo
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-oauth-openid-connect-sdk">Nimbus OAuth 2.0 SDK</a>
 */
public class NimbusOAuth2UserService implements OAuth2UserService {
	private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";
	private final HttpMessageConverter jackson2HttpMessageConverter = new MappingJackson2HttpMessageConverter();
	private Map<URI, String> userNameAttributeNames = Collections.unmodifiableMap(Collections.emptyMap());
	private Map<URI, Class<? extends OAuth2User>> customUserTypes = Collections.unmodifiableMap(Collections.emptyMap());
	private HttpClientConfig httpClientConfig = new HttpClientConfig();

	public NimbusOAuth2UserService() {
	}

	@Override
	public final OAuth2User loadUser(OAuth2AuthenticationToken token) throws OAuth2AuthenticationException {
		URI userInfoUri = this.getUserInfoUri(token);

		if (this.getCustomUserTypes().containsKey(userInfoUri)) {
			return this.loadCustomUser(token);
		}
		if (token.getIdToken() != null) {
			return this.loadOidcUser(token);
		}

		return this.loadOAuth2User(token);
	}

	protected OAuth2User loadOidcUser(OAuth2AuthenticationToken token) throws OAuth2AuthenticationException {
		// TODO Retrieving the UserInfo should be optional. Need to add the capability for opting in/out
		Map<String, Object> userAttributes = this.getUserInfo(token);
		UserInfo userInfo = new UserInfo(userAttributes);

		GrantedAuthority authority = new OidcUserAuthority(token.getIdToken(), userInfo);
		Set<GrantedAuthority> authorities = new HashSet<>();
		authorities.add(authority);

		return new DefaultOidcUser(authorities, token.getIdToken(), userInfo);
	}

	protected OAuth2User loadOAuth2User(OAuth2AuthenticationToken token) throws OAuth2AuthenticationException {
		URI userInfoUri = this.getUserInfoUri(token);
		if (!this.getUserNameAttributeNames().containsKey(userInfoUri)) {
			throw new IllegalArgumentException("The attribute name for the \"user's name\" is required for the OAuth2User " +
				" retrieved from the UserInfo Endpoint -> " + userInfoUri.toString());
		}
		String userNameAttributeName = this.getUserNameAttributeNames().get(userInfoUri);

		Map<String, Object> userAttributes = this.getUserInfo(token);

		GrantedAuthority authority = new OAuth2UserAuthority(userAttributes);
		Set<GrantedAuthority> authorities = new HashSet<>();
		authorities.add(authority);

		return new DefaultOAuth2User(authorities, userAttributes, userNameAttributeName);
	}

	protected OAuth2User loadCustomUser(OAuth2AuthenticationToken token) throws OAuth2AuthenticationException {
		URI userInfoUri = this.getUserInfoUri(token);
		Class<? extends OAuth2User> customUserType = this.getCustomUserTypes().get(userInfoUri);

		OAuth2User user;
		try {
			user = customUserType.newInstance();
		} catch (ReflectiveOperationException ex) {
			throw new IllegalArgumentException("An error occurred while attempting to instantiate the custom OAuth2User \"" +
				customUserType.getName() + "\" -> " + ex.getMessage(), ex);
		}

		Map<String, Object> userAttributes = this.getUserInfo(token);
		if (token.getIdToken() != null) {
			userAttributes.putAll(token.getIdToken().getClaims());
		}

		BeanWrapper wrapper = PropertyAccessorFactory.forBeanPropertyAccess(user);
		wrapper.setAutoGrowNestedPaths(true);
		wrapper.setPropertyValues(userAttributes);

		return user;
	}

	protected Map<String, Object> getUserInfo(OAuth2AuthenticationToken token) throws OAuth2AuthenticationException {
		URI userInfoUri = this.getUserInfoUri(token);

		BearerAccessToken accessToken = new BearerAccessToken(token.getAccessToken().getTokenValue());

		UserInfoRequest userInfoRequest = new UserInfoRequest(userInfoUri, accessToken);
		HTTPRequest httpRequest = userInfoRequest.toHTTPRequest();
		httpRequest.setAccept(MediaType.APPLICATION_JSON_VALUE);
		httpRequest.setConnectTimeout(this.httpClientConfig.getConnectTimeout());
		httpRequest.setReadTimeout(this.httpClientConfig.getReadTimeout());
		HTTPResponse httpResponse;

		try {
			httpResponse = httpRequest.send();
		} catch (IOException ex) {
			throw new AuthenticationServiceException("An error occurred while sending the UserInfo Request: " +
				ex.getMessage(), ex);
		}

		if (httpResponse.getStatusCode() != HTTPResponse.SC_OK) {
			UserInfoErrorResponse userInfoErrorResponse;
			try {
				userInfoErrorResponse = UserInfoErrorResponse.parse(httpResponse);
			} catch (ParseException ex) {
				OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE,
					"An error occurred parsing the UserInfo Error response: " + ex.getMessage(), null);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
			}
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

		try {
			return (Map<String, Object>) this.jackson2HttpMessageConverter.read(Map.class, new NimbusClientHttpResponse(httpResponse));
		} catch (IOException ex) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE,
				"An error occurred reading the UserInfo Success response: " + ex.getMessage(), null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
		}
	}

	protected Map<URI, String> getUserNameAttributeNames() {
		return this.userNameAttributeNames;
	}

	public final void setUserNameAttributeNames(Map<URI, String> userNameAttributeNames) {
		Assert.notEmpty(userNameAttributeNames, "userNameAttributeNames cannot be empty");
		this.userNameAttributeNames = Collections.unmodifiableMap(new HashMap<>(userNameAttributeNames));
	}

	protected Map<URI, Class<? extends OAuth2User>> getCustomUserTypes() {
		return this.customUserTypes;
	}

	public final void setCustomUserTypes(Map<URI, Class<? extends OAuth2User>> customUserTypes) {
		Assert.notEmpty(customUserTypes, "customUserTypes cannot be empty");
		this.customUserTypes = Collections.unmodifiableMap(new HashMap<>(customUserTypes));
	}

	public final void setHttpClientConfig(HttpClientConfig httpClientConfig) {
		Assert.notNull(httpClientConfig, "httpClientConfig cannot be null");
		this.httpClientConfig = httpClientConfig;
	}

	private URI getUserInfoUri(OAuth2AuthenticationToken token) {
		ClientRegistration clientRegistration = token.getClientRegistration();
		try {
			return new URI(clientRegistration.getProviderDetails().getUserInfoUri());
		} catch (Exception ex) {
			throw new IllegalArgumentException("An error occurred parsing the UserInfo URI: " +
				clientRegistration.getProviderDetails().getUserInfoUri(), ex);
		}
	}
}
