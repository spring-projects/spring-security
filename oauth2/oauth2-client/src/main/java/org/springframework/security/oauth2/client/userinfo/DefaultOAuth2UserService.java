/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.userinfo;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * An implementation of an {@link OAuth2UserService} that supports standard OAuth 2.0 Provider's.
 * <p>
 * For standard OAuth 2.0 Provider's, the attribute name used to access the user's name
 * from the UserInfo response is required and therefore must be available via
 * {@link org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails.UserInfoEndpoint#getUserNameAttributeName() UserInfoEndpoint.getUserNameAttributeName()}.
 * <p>
 * <b>NOTE:</b> Attribute names are <b>not</b> standardized between providers and therefore will vary.
 * Please consult the provider's API documentation for the set of supported user attribute names.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2UserService
 * @see OAuth2UserRequest
 * @see OAuth2User
 * @see DefaultOAuth2User
 */
public class DefaultOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
	private static final String MISSING_USER_INFO_URI_ERROR_CODE = "missing_user_info_uri";
	private static final String MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE = "missing_user_name_attribute";
	private NimbusUserInfoResponseClient userInfoResponseClient = new NimbusUserInfoResponseClient();

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		Assert.notNull(userRequest, "userRequest cannot be null");

		if (!StringUtils.hasText(userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri())) {
			OAuth2Error oauth2Error = new OAuth2Error(
				MISSING_USER_INFO_URI_ERROR_CODE,
				"Missing required UserInfo Uri in UserInfoEndpoint for Client Registration: " +
					userRequest.getClientRegistration().getRegistrationId(),
				null
			);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
		if (!StringUtils.hasText(userNameAttributeName)) {
			OAuth2Error oauth2Error = new OAuth2Error(
				MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE,
				"Missing required \"user name\" attribute name in UserInfoEndpoint for Client Registration: " +
					userRequest.getClientRegistration().getRegistrationId(),
				null
			);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		ParameterizedTypeReference<Map<String, Object>> typeReference =
			new ParameterizedTypeReference<Map<String, Object>>() {};
		Map<String, Object> userAttributes = this.userInfoResponseClient.getUserInfoResponse(userRequest, typeReference);
		GrantedAuthority authority = new OAuth2UserAuthority(userAttributes);
		Set<GrantedAuthority> authorities = new HashSet<>();
		authorities.add(authority);

		return new DefaultOAuth2User(authorities, userAttributes, userNameAttributeName);
	}
}
