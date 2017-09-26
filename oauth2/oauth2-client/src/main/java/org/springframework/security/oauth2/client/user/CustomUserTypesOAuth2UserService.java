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
package org.springframework.security.oauth2.client.user;

import org.springframework.beans.BeanWrapper;
import org.springframework.beans.PropertyAccessorFactory;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.client.user.nimbus.NimbusUserInfoRetriever;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.oidc.client.authentication.OidcClientAuthenticationToken;
import org.springframework.util.Assert;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An implementation of an {@link OAuth2UserService} that supports custom {@link OAuth2User} types.
 * <p>
 * The custom user type(s) is supplied via the constructor,
 * using a <code>Map</code> of {@link OAuth2User} type <i>keyed</i> by <code>URI</code>,
 * representing the <i>UserInfo Endpoint</i> address.
 * <p>
 * This implementation uses a {@link UserInfoRetriever} to obtain the user attributes
 * of the <i>End-User</i> (resource owner) from the <i>UserInfo Endpoint</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2UserService
 * @see OAuth2User
 * @see UserInfoRetriever
 */
public class CustomUserTypesOAuth2UserService implements OAuth2UserService {
	private final Map<URI, Class<? extends OAuth2User>> customUserTypes;
	private UserInfoRetriever userInfoRetriever = new NimbusUserInfoRetriever();

	public CustomUserTypesOAuth2UserService(Map<URI, Class<? extends OAuth2User>> customUserTypes) {
		Assert.notEmpty(customUserTypes, "customUserTypes cannot be empty");
		this.customUserTypes = Collections.unmodifiableMap(new LinkedHashMap<>(customUserTypes));
	}

	@Override
	public OAuth2User loadUser(OAuth2ClientAuthenticationToken clientAuthentication) throws OAuth2AuthenticationException {
		URI userInfoUri = URI.create(clientAuthentication.getClientRegistration().getProviderDetails().getUserInfoUri());
		Class<? extends OAuth2User> customUserType;
		if ((customUserType = this.getCustomUserTypes().get(userInfoUri)) == null) {
			return null;
		}

		OAuth2User customUser;
		try {
			customUser = customUserType.newInstance();
		} catch (ReflectiveOperationException ex) {
			throw new IllegalArgumentException("An error occurred while attempting to instantiate the custom OAuth2User \"" +
				customUserType.getName() + "\": " + ex.getMessage(), ex);
		}

		Map<String, Object> userAttributes = this.userInfoRetriever.retrieve(clientAuthentication);
		if (OidcClientAuthenticationToken.class.isAssignableFrom(clientAuthentication.getClass())) {
			userAttributes.putAll(((OidcClientAuthenticationToken)clientAuthentication).getIdToken().getClaims());
		}

		BeanWrapper wrapper = PropertyAccessorFactory.forBeanPropertyAccess(customUser);
		wrapper.setAutoGrowNestedPaths(true);
		wrapper.setPropertyValues(userAttributes);

		return customUser;
	}

	protected Map<URI, Class<? extends OAuth2User>> getCustomUserTypes() {
		return this.customUserTypes;
	}

	protected UserInfoRetriever getUserInfoRetriever() {
		return this.userInfoRetriever;
	}

	public final void setUserInfoRetriever(UserInfoRetriever userInfoRetriever) {
		Assert.notNull(userInfoRetriever, "userInfoRetriever cannot be null");
		this.userInfoRetriever = userInfoRetriever;
	}
}
