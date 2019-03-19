package org.springframework.security.test.context.support.oauth2.support;

import static org.junit.Assert.assertFalse;
import static org.springframework.security.test.context.support.oauth2.support.CollectionsSupport.putIfNotEmpty;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.util.StringUtils;

public class OidcIdSupport {
	public static final String DEFAULT_TOKEN_VALUE = "Open ID test";
	public static final String DEFAULT_AUTH_NAME = "user";
	public static final String DEFAULT_NAME_KEY = "sub";
	public static final String[] DEFAULT_AUTHORITIES = { "ROLE_USER" };
	public static final String REQUEST_REDIRECT_URI = "https://localhost:8080/";
	public static final String REQUEST_AUTHORIZATION_URI = "https://localhost:8080/authorize";
	public static final String REQUEST_GRANT_TYPE = "authorization_code";
	public static final String CLIENT_TOKEN_URI = "https://localhost:8080/token";
	public static final String CLIENT_ID = "mocked-client";
	public static final String CLIENT_REGISTRATION_ID = "mocked-registration";
	public static final String CLIENT_GRANT_TYPE = "client_credentials";

	private final AuthoritiesAndScopes authoritiesAndScopes;

	private final Map<String, Object> claims;

	public OidcIdSupport(
			final Collection<String> authorities,
			final Collection<String> scopes,
			final Map<String, Object> additionalClaims) {
		claims = new HashMap<>(additionalClaims);
		authoritiesAndScopes = AuthoritiesAndScopes.get(authorities, scopes, claims);
	}

	public Set<? extends GrantedAuthority> getAllAuthorities() {
		return authoritiesAndScopes.authorities;
	}

	public Set<String> getAllScopes() {
		return authoritiesAndScopes.scopes;
	}

	public OAuth2LoginAuthenticationToken authentication(
			final String name,
			final String nameAttributeKey,
			final ClientRegistration.Builder clientRegistrationBuilder,
			final OAuth2AuthorizationRequest.Builder authorizationRequestBuilder) {
		assertFalse(StringUtils.isEmpty(nameAttributeKey));
		assertFalse(
				nameAttributeKey + " claim is not configurable: forced to name",
				claims.containsKey(nameAttributeKey));

		putIfNotEmpty(nameAttributeKey, name, claims);

		final OidcIdToken token = new OidcIdToken(
				DEFAULT_TOKEN_VALUE,
				(Instant) claims.get(IdTokenClaimNames.IAT),
				(Instant) claims.get(IdTokenClaimNames.EXP),
				claims);

		final ClientRegistration clientRegistration = clientRegistrationBuilder.scope(authoritiesAndScopes.scopes)
				.userNameAttributeName(nameAttributeKey)
				.build();

		final OAuth2AuthorizationRequest authorizationRequest =
				authorizationRequestBuilder.attributes(claims).scopes(authoritiesAndScopes.scopes).build();

		final String redirectUri =
				StringUtils.isEmpty(authorizationRequest.getRedirectUri()) ? clientRegistration.getRedirectUriTemplate()
						: authorizationRequest.getRedirectUri();

		final OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(authorizationRequest, auth2AuthorizationResponse(redirectUri));

		final DefaultOidcUser principal =
				new DefaultOidcUser(authoritiesAndScopes.authorities, token, nameAttributeKey);

		final OAuth2AccessToken accessToken = new OAuth2AccessToken(
				TokenType.BEARER,
				DEFAULT_TOKEN_VALUE,
				(Instant) claims.get(IdTokenClaimNames.IAT),
				(Instant) claims.get(IdTokenClaimNames.EXP),
				authorizationExchange.getAuthorizationRequest().getScopes());

		return new OAuth2LoginAuthenticationToken(
				clientRegistration,
				authorizationExchange,
				principal,
				authoritiesAndScopes.authorities,
				accessToken);
	}

	public static OAuth2AuthorizationRequest.Builder
			authorizationRequestBuilder(final AuthorizationGrantType authorizationGrantType) {
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
			return OAuth2AuthorizationRequest.authorizationCode();
		}
		if (AuthorizationGrantType.IMPLICIT.equals(authorizationGrantType)) {
			return OAuth2AuthorizationRequest.implicit();
		}
		throw new UnsupportedOperationException(
				"Only authorization_code and implicit grant types are supported for MockOAuth2AuthorizationRequest");
	}

	private static OAuth2AuthorizationResponse auth2AuthorizationResponse(final String redirectUri) {
		final OAuth2AuthorizationResponse.Builder builder =
				OAuth2AuthorizationResponse.success("test-authorization-success-code");
		builder.redirectUri(redirectUri);
		return builder.build();
	}
}
