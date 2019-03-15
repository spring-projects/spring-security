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

package org.springframework.security.oauth2.client.oidc.userinfo;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * Utilities for working with the {@link OidcUserRequest}
 *
 * @author Rob Winch
 * @since 5.1
 */
final class OidcUserRequestUtils {

	/**
	 * Determines if an {@link OidcUserRequest} should attempt to retrieve the user info endpoint. Will return true if
	 * all of the following are true:
	 *
	 * <ul>
	 *     <li>The user info endpoint is defined on the ClientRegistration</li>
	 *     <li>The Client Registration uses the {@link AuthorizationGrantType#AUTHORIZATION_CODE} and scopes in the
	 *       access token are defined in the {@link ClientRegistration}</li>
	 * </ul>
	 * @param userRequest
	 * @return
	 */
	static boolean shouldRetrieveUserInfo(OidcUserRequest userRequest) {
		// Auto-disabled if UserInfo Endpoint URI is not provided
		ClientRegistration clientRegistration = userRequest.getClientRegistration();
		if (StringUtils.isEmpty(clientRegistration.getProviderDetails()
				.getUserInfoEndpoint().getUri())) {

			return false;
		}

		// The Claims requested by the profile, email, address, and phone scope values
		// are returned from the UserInfo Endpoint (as described in Section 5.3.2),
		// when a response_type value is used that results in an Access Token being issued.
		// However, when no Access Token is issued, which is the case for the response_type=id_token,
		// the resulting Claims are returned in the ID Token.
		// The Authorization Code Grant Flow, which is response_type=code, results in an Access Token being issued.
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {

			// Return true if there is at least one match between the authorized scope(s) and UserInfo scope(s)
			return CollectionUtils
					.containsAny(userRequest.getAccessToken().getScopes(), userRequest.getClientRegistration().getScopes());
		}

		return false;
	}

	private OidcUserRequestUtils() {}
}
