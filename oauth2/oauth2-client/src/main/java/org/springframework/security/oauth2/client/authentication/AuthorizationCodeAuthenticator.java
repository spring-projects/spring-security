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
package org.springframework.security.oauth2.client.authentication;

import org.springframework.security.oauth2.client.web.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.endpoint.TokenResponseAttributes;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link AuthorizationGrantAuthenticator} that
 * <i>&quot;authenticates&quot;</i> an <i>authorization code grant</i> credential
 * against an OAuth 2.0 Provider's <i>Token Endpoint</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 */
public class AuthorizationCodeAuthenticator implements AuthorizationGrantAuthenticator<AuthorizationCodeAuthenticationToken> {
	private final AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger;

	public AuthorizationCodeAuthenticator(AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger) {
		Assert.notNull(authorizationCodeTokenExchanger, "authorizationCodeTokenExchanger cannot be null");
		this.authorizationCodeTokenExchanger = authorizationCodeTokenExchanger;
	}

	@Override
	public OAuth2ClientAuthenticationToken authenticate(
		AuthorizationCodeAuthenticationToken authorizationCodeAuthentication) throws OAuth2AuthenticationException {

		// Section 3.1.2.1 Authentication Request - http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
		// scope
		// 		REQUIRED. OpenID Connect requests MUST contain the "openid" scope value.
		//		If the openid scope value is not present, the behavior is entirely unspecified.
		if (authorizationCodeAuthentication.getAuthorizationRequest().getScope().contains("openid")) {
			// The OpenID Connect implementation of AuthorizationGrantAuthenticator
			// must handle OpenID Connect Authentication Requests
			return null;
		}

		TokenResponseAttributes tokenResponse =
			this.authorizationCodeTokenExchanger.exchange(authorizationCodeAuthentication);

		AccessToken accessToken = new AccessToken(tokenResponse.getTokenType(),
			tokenResponse.getTokenValue(), tokenResponse.getIssuedAt(),
			tokenResponse.getExpiresAt(), tokenResponse.getScope());

		OAuth2ClientAuthenticationToken oauth2ClientAuthentication =
			new OAuth2ClientAuthenticationToken(authorizationCodeAuthentication.getClientRegistration(), accessToken);
		oauth2ClientAuthentication.setDetails(authorizationCodeAuthentication.getDetails());

		return oauth2ClientAuthentication;
	}
}
