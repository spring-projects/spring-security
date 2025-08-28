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

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UsernameExpressionUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * Utilities for working with the {@link OidcUserRequest}
 *
 * @author Rob Winch
 * @author Yoobin Yoon
 * @since 5.1
 */
final class OidcUserRequestUtils {

	/**
	 * Determines if an {@link OidcUserRequest} should attempt to retrieve the user info
	 * endpoint. Will return true if all of the following are true:
	 *
	 * <ul>
	 * <li>The user info endpoint is defined on the ClientRegistration</li>
	 * <li>The Client Registration uses the
	 * {@link AuthorizationGrantType#AUTHORIZATION_CODE} and scopes in the access token
	 * are defined in the {@link ClientRegistration}</li>
	 * </ul>
	 * @param userRequest
	 * @return
	 */
	static boolean shouldRetrieveUserInfo(OidcUserRequest userRequest) {
		// Auto-disabled if UserInfo Endpoint URI is not provided
		ClientRegistration clientRegistration = userRequest.getClientRegistration();
		if (!StringUtils.hasLength(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri())) {
			return false;
		}
		// The Claims requested by the profile, email, address, and phone scope values
		// are returned from the UserInfo Endpoint (as described in Section 5.3.2),
		// when a response_type value is used that results in an Access Token being
		// issued.
		// However, when no Access Token is issued, which is the case for the
		// response_type=id_token,
		// the resulting Claims are returned in the ID Token.
		// The Authorization Code Grant Flow, which is response_type=code, results in an
		// Access Token being issued.
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
			// Return true if there is at least one match between the authorized scope(s)
			// and UserInfo scope(s)
			return CollectionUtils.containsAny(userRequest.getAccessToken().getScopes(),
					userRequest.getClientRegistration().getScopes());
		}
		return false;
	}

	static OidcUser getUser(OidcUserSource userMetadata) {
		OidcUserRequest userRequest = userMetadata.getUserRequest();
		OidcUserInfo userInfo = userMetadata.getUserInfo();
		Set<GrantedAuthority> authorities = new LinkedHashSet<>();
		ClientRegistration.ProviderDetails providerDetails = userRequest.getClientRegistration().getProviderDetails();
		String usernameExpression = providerDetails.getUserInfoEndpoint().getUsernameExpression();

		String username;
		if (StringUtils.hasText(usernameExpression)) {
			Map<String, Object> claims = collectClaims(userRequest.getIdToken(), userInfo);
			username = OAuth2UsernameExpressionUtils.evaluateUsername(claims, usernameExpression);
		}
		else {
			username = userRequest.getIdToken().getSubject();
		}

		authorities
			.add(OidcUserAuthority.withUsername(username).idToken(userRequest.getIdToken()).userInfo(userInfo).build());

		OAuth2AccessToken token = userRequest.getAccessToken();
		for (String scope : token.getScopes()) {
			authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
		}

		return DefaultOidcUser.withUsername(username)
			.authorities(authorities)
			.idToken(userRequest.getIdToken())
			.userInfo(userInfo)
			.build();
	}

	private static Map<String, Object> collectClaims(OidcIdToken idToken, OidcUserInfo userInfo) {
		Assert.notNull(idToken, "idToken cannot be null");
		Map<String, Object> claims = new HashMap<>();
		if (userInfo != null) {
			claims.putAll(userInfo.getClaims());
		}
		claims.putAll(idToken.getClaims());
		return claims;
	}

	private OidcUserRequestUtils() {
	}

}
