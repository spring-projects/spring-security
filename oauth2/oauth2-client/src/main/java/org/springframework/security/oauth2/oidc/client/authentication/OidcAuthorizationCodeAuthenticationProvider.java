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
package org.springframework.security.oauth2.oidc.client.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.jwt.JwtDecoderRegistry;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.TokenResponse;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.oidc.client.userinfo.OidcUserService;
import org.springframework.security.oauth2.oidc.core.IdToken;
import org.springframework.security.oauth2.oidc.core.OidcScope;
import org.springframework.security.oauth2.oidc.core.endpoint.OidcParameter;
import org.springframework.security.oauth2.oidc.core.user.OidcUser;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.List;

/**
 * An implementation of an {@link AuthenticationProvider}
 * for the <i>OpenID Connect Core 1.0 Authorization Code Grant Flow</i>.
 * <p>
 * This {@link AuthenticationProvider} is responsible for authenticating
 * an <i>authorization code</i> credential with the authorization server's <i>Token Endpoint</i>
 * and if valid, exchanging it for an <i>access token</i> credential.
 * <p>
 * It will also obtain the user attributes of the <i>End-User</i> (resource owner)
 * from the <i>UserInfo Endpoint</i> using an {@link OAuth2UserService}
 * which will create a <code>Principal</code> in the form of an {@link OidcUser}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationCodeAuthenticationToken
 * @see OAuth2AuthenticationToken
 * @see OidcAuthorizedClient
 * @see OidcUserService
 * @see OidcUser
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">Section 3.1 Authorization Code Grant Flow</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#TokenRequest">Section 3.1.3.1 Token Request</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse">Section 3.1.3.3 Token Response</a>
 */
public class OidcAuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
	private static final String INVALID_STATE_PARAMETER_ERROR_CODE = "invalid_state_parameter";
	private static final String INVALID_REDIRECT_URI_PARAMETER_ERROR_CODE = "invalid_redirect_uri_parameter";
	private static final String INVALID_ID_TOKEN_ERROR_CODE = "invalid_id_token";
	private final AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger;
	private final OAuth2UserService userService;
	private final JwtDecoderRegistry jwtDecoderRegistry;
	private GrantedAuthoritiesMapper authoritiesMapper = (authorities -> authorities);

	public OidcAuthorizationCodeAuthenticationProvider(
		AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> authorizationCodeTokenExchanger,
		OAuth2UserService userService,
		JwtDecoderRegistry jwtDecoderRegistry) {

		Assert.notNull(authorizationCodeTokenExchanger, "authorizationCodeTokenExchanger cannot be null");
		Assert.notNull(userService, "userService cannot be null");
		Assert.notNull(jwtDecoderRegistry, "jwtDecoderRegistry cannot be null");
		this.authorizationCodeTokenExchanger = authorizationCodeTokenExchanger;
		this.userService = userService;
		this.jwtDecoderRegistry = jwtDecoderRegistry;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		AuthorizationCodeAuthenticationToken authorizationCodeAuthentication =
				(AuthorizationCodeAuthenticationToken) authentication;

		// Section 3.1.2.1 Authentication Request - http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
		// scope
		// 		REQUIRED. OpenID Connect requests MUST contain the "openid" scope value.
		if (!authorizationCodeAuthentication.getAuthorizationExchange()
			.getAuthorizationRequest().getScopes().contains(OidcScope.OPENID)) {
			// This is NOT an OpenID Connect Authentication Request so return null
			// and let OAuth2LoginAuthenticationProvider handle it instead
			return null;
		}

		AuthorizationRequest authorizationRequest = authorizationCodeAuthentication
			.getAuthorizationExchange().getAuthorizationRequest();
		AuthorizationResponse authorizationResponse = authorizationCodeAuthentication
			.getAuthorizationExchange().getAuthorizationResponse();

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

		TokenResponse tokenResponse =
			this.authorizationCodeTokenExchanger.exchange(authorizationCodeAuthentication);

		AccessToken accessToken = new AccessToken(tokenResponse.getTokenType(),
			tokenResponse.getTokenValue(), tokenResponse.getIssuedAt(),
			tokenResponse.getExpiresAt(), tokenResponse.getScopes());

		ClientRegistration clientRegistration = authorizationCodeAuthentication.getClientRegistration();

		if (!tokenResponse.getAdditionalParameters().containsKey(OidcParameter.ID_TOKEN)) {
			throw new IllegalArgumentException(
				"Missing (required) ID Token in Token Response for Client Registration: " + clientRegistration.getRegistrationId());
		}

		JwtDecoder jwtDecoder = this.jwtDecoderRegistry.getJwtDecoder(clientRegistration);
		if (jwtDecoder == null) {
			throw new IllegalArgumentException("Failed to find a registered JwtDecoder for Client Registration: '" +
				clientRegistration.getRegistrationId() + "'. Check to ensure you have configured the JwkSet URI.");
		}
		Jwt jwt = jwtDecoder.decode((String)tokenResponse.getAdditionalParameters().get(OidcParameter.ID_TOKEN));
		IdToken idToken = new IdToken(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaims());

		this.validateIdToken(idToken, clientRegistration);

		OidcAuthorizedClient authorizedClient = new OidcAuthorizedClient(
			clientRegistration, idToken.getSubject(), accessToken, idToken);

		OAuth2User oauth2User = this.userService.loadUser(authorizedClient);

		// Update AuthorizedClient as the 'principalName' may have changed
		// (the default IdToken.subject) from the result of userService.loadUser()
		authorizedClient = new OidcAuthorizedClient(
			clientRegistration, oauth2User.getName(), accessToken, idToken);

		Collection<? extends GrantedAuthority> mappedAuthorities =
			this.authoritiesMapper.mapAuthorities(oauth2User.getAuthorities());

		OAuth2AuthenticationToken authenticationResult = new OAuth2AuthenticationToken(
			oauth2User, mappedAuthorities, authorizedClient);
		authenticationResult.setDetails(authorizationCodeAuthentication.getDetails());

		return authenticationResult;
	}

	public final void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
		this.authoritiesMapper = authoritiesMapper;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private void validateIdToken(IdToken idToken, ClientRegistration clientRegistration) {
		// 3.1.3.7  ID Token Validation
		// http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

		// Validate REQUIRED Claims
		URL issuer = idToken.getIssuer();
		if (issuer == null) {
			this.throwInvalidIdTokenException();
		}
		String subject = idToken.getSubject();
		if (subject == null) {
			this.throwInvalidIdTokenException();
		}
		List<String> audience = idToken.getAudience();
		if (CollectionUtils.isEmpty(audience)) {
			this.throwInvalidIdTokenException();
		}
		Instant expiresAt = idToken.getExpiresAt();
		if (expiresAt == null) {
			this.throwInvalidIdTokenException();
		}
		Instant issuedAt = idToken.getIssuedAt();
		if (issuedAt == null) {
			this.throwInvalidIdTokenException();
		}

		// 2. The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
		// MUST exactly match the value of the iss (issuer) Claim.
		// TODO Depends on gh-4413

		// 3. The Client MUST validate that the aud (audience) Claim contains its client_id value
		// registered at the Issuer identified by the iss (issuer) Claim as an audience.
		// The aud (audience) Claim MAY contain an array with more than one element.
		// The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience,
		// or if it contains additional audiences not trusted by the Client.
		if (!audience.contains(clientRegistration.getClientId())) {
			this.throwInvalidIdTokenException();
		}

		// 4. If the ID Token contains multiple audiences,
		// the Client SHOULD verify that an azp Claim is present.
		String authorizedParty = idToken.getAuthorizedParty();
		if (audience.size() > 1 && authorizedParty == null) {
			this.throwInvalidIdTokenException();
		}

		// 5. If an azp (authorized party) Claim is present,
		// the Client SHOULD verify that its client_id is the Claim Value.
		if (authorizedParty != null && !authorizedParty.equals(clientRegistration.getClientId())) {
			this.throwInvalidIdTokenException();
		}

		// 7. The alg value SHOULD be the default of RS256 or the algorithm sent by the Client
		// in the id_token_signed_response_alg parameter during Registration.
		// TODO Depends on gh-4413

		// 9. The current time MUST be before the time represented by the exp Claim.
		Instant now = Instant.now();
		if (!now.isBefore(expiresAt)) {
			this.throwInvalidIdTokenException();
		}

		// 10. The iat Claim can be used to reject tokens that were issued too far away from the current time,
		// limiting the amount of time that nonces need to be stored to prevent attacks.
		// The acceptable range is Client specific.
		Instant maxIssuedAt = now.plusSeconds(30);
		if (issuedAt.isAfter(maxIssuedAt)) {
			this.throwInvalidIdTokenException();
		}

		// 11. If a nonce value was sent in the Authentication Request,
		// a nonce Claim MUST be present and its value checked to verify
		// that it is the same value as the one that was sent in the Authentication Request.
		// The Client SHOULD check the nonce value for replay attacks.
		// The precise method for detecting replay attacks is Client specific.
		// TODO Depends on gh-4442

	}

	private void throwInvalidIdTokenException() {
		OAuth2Error invalidIdTokenError = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE);
		throw new OAuth2AuthenticationException(invalidIdTokenError, invalidIdTokenError.toString());
	}
}
