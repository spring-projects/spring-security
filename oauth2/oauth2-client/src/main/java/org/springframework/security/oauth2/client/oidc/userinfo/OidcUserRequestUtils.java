/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.userinfo;

import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.util.StringUtils;

/**
 * Utilities for working with the {@link OidcUserRequest}
 *
 * @author Rob Winch
 * @since 5.1
 */
final class OidcUserRequestUtils {

	/**
	 * Determines if an {@link OidcUserRequest} should attempt to retrieve the user info.
	 * Will return true if all the following are true:
	 *
	 * <ul>
	 * <li>The user info endpoint is defined on the ClientRegistration</li>
	 * <li>The Client Registration uses the
	 * {@link AuthorizationGrantType#AUTHORIZATION_CODE}</li>
	 * </ul>
	 * @param userRequest
	 * @return
	 */
	static boolean shouldRetrieveUserInfo(OidcUserRequest userRequest) {
		// Auto-disabled if UserInfo Endpoint URI is not provided
		ClientRegistration.ProviderDetails providerDetails = userRequest.getClientRegistration().getProviderDetails();
		if (StringUtils.hasLength(providerDetails.getUserInfoEndpoint().getUri())
				&& AuthorizationGrantType.AUTHORIZATION_CODE
					.equals(userRequest.getClientRegistration().getAuthorizationGrantType())) {
			return true;
		}
		return false;
	}

	static OidcUser getUser(OidcUserSource userMetadata) {
		OidcUserRequest userRequest = userMetadata.getUserRequest();
		OidcUserInfo userInfo = userMetadata.getUserInfo();
		Set<GrantedAuthority> authorities = new LinkedHashSet<>();
		ClientRegistration.ProviderDetails providerDetails = userRequest.getClientRegistration().getProviderDetails();
		String userNameAttributeName = providerDetails.getUserInfoEndpoint().getUserNameAttributeName();
		if (StringUtils.hasText(userNameAttributeName)) {
			authorities.add(new OidcUserAuthority(userRequest.getIdToken(), userInfo, userNameAttributeName));
		}
		else {
			authorities.add(new OidcUserAuthority(userRequest.getIdToken(), userInfo));
		}
		OAuth2AccessToken token = userRequest.getAccessToken();
		for (String scope : token.getScopes()) {
			authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
		}
		if (StringUtils.hasText(userNameAttributeName)) {
			return new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo, userNameAttributeName);
		}
		return new DefaultOidcUser(authorities, userRequest.getIdToken(), userInfo);
	}

	private OidcUserRequestUtils() {
	}

}
