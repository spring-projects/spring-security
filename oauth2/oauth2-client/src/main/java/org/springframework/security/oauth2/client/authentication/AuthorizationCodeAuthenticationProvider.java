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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.token.InMemoryAccessTokenRepository;
import org.springframework.security.oauth2.client.token.SecurityTokenRepository;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.AuthorizationResponse;
import org.springframework.security.oauth2.oidc.client.authentication.OidcClientAuthenticationToken;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link AuthenticationProvider} that is responsible for authenticating
 * an <i>authorization code</i> credential with the authorization server's <i>Token Endpoint</i>
 * and if valid, exchanging it for an <i>access token</i> credential and optionally an
 * <i>id token</i> credential (for OpenID Connect Authorization Code Flow).
 *
 * <p>
 * The {@link AuthorizationCodeAuthenticationProvider} uses an {@link AuthorizationGrantAuthenticator}
 * to authenticate the <i>authorization code</i> credential and ultimately
 * return an <i>&quot;Authorized Client&quot;</i> as an {@link OAuth2ClientAuthenticationToken}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationCodeAuthenticationToken
 * @see OAuth2ClientAuthenticationToken
 * @see OidcClientAuthenticationToken
 * @see AuthorizationGrantAuthenticator
 * @see SecurityTokenRepository
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant Flow</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">Section 3.1 OpenID Connect Authorization Code Flow</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.4">Section 4.1.4 Access Token Response</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">Section 3.1.3.3 OpenID Connect Token Response</a>
 */
public class AuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
	private static final String INVALID_STATE_PARAMETER_ERROR_CODE = "invalid_state_parameter";
	private static final String INVALID_REDIRECT_URI_PARAMETER_ERROR_CODE = "invalid_redirect_uri_parameter";
	private final AuthorizationGrantAuthenticator<AuthorizationCodeAuthenticationToken> authorizationCodeAuthenticator;
	private SecurityTokenRepository<AccessToken> accessTokenRepository = new InMemoryAccessTokenRepository();

	public AuthorizationCodeAuthenticationProvider(
		AuthorizationGrantAuthenticator<AuthorizationCodeAuthenticationToken> authorizationCodeAuthenticator) {

		Assert.notNull(authorizationCodeAuthenticator, "authorizationCodeAuthenticator cannot be null");
		this.authorizationCodeAuthenticator = authorizationCodeAuthenticator;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		AuthorizationCodeAuthenticationToken authorizationCodeAuthentication =
				(AuthorizationCodeAuthenticationToken) authentication;

		AuthorizationRequest authorizationRequest = authorizationCodeAuthentication.getAuthorizationRequest();
		AuthorizationResponse authorizationResponse = authorizationCodeAuthentication.getAuthorizationResponse();

		if (authorizationResponse.statusError()) {
			throw new OAuth2AuthenticationException(
				authorizationResponse.getError(), authorizationResponse.getError().toString());
		}

		if (!authorizationResponse.getState().equals(authorizationRequest.getState())) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_STATE_PARAMETER_ERROR_CODE);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		if (!authorizationResponse.getRedirectUri().equals(authorizationRequest.getRedirectUri())) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_REDIRECT_URI_PARAMETER_ERROR_CODE);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		OAuth2ClientAuthenticationToken oauth2ClientAuthentication =
			this.authorizationCodeAuthenticator.authenticate(authorizationCodeAuthentication);

		this.accessTokenRepository.saveSecurityToken(
			oauth2ClientAuthentication.getAccessToken(),
			oauth2ClientAuthentication.getClientRegistration());

		return oauth2ClientAuthentication;
	}

	public final void setAccessTokenRepository(SecurityTokenRepository<AccessToken> accessTokenRepository) {
		Assert.notNull(accessTokenRepository, "accessTokenRepository cannot be null");
		this.accessTokenRepository = accessTokenRepository;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
