package org.springframework.security.test.context.support.oauth2.support;

import static org.springframework.security.test.context.support.oauth2.support.CollectionsSupport.nullIfEmpty;
import static org.springframework.security.test.context.support.oauth2.support.CollectionsSupport.putIfNotEmpty;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames;

public class AccessTokenSupport {
	public static final String DEFAULT_TOKEN_VALUE = "Bearer test";
	public static final String DEFAULT_AUTH_NAME = "user";
	public static final String[] DEFAULT_AUTHORITIES = { "ROLE_USER" };

	public static final OAuth2IntrospectionAuthenticationToken authentication(
			final String username,
			final Collection<String> authorities,
			final Collection<String> scopes,
			final Map<String, Object> attributes) {
		final Map<String, Object> postrPocessedAttributes = new HashMap<>(attributes);

		if (attributes.containsKey(OAuth2IntrospectionClaimNames.TOKEN_TYPE)) {
			throw new RuntimeException(
					OAuth2IntrospectionClaimNames.TOKEN_TYPE
							+ " claim is not configurable (forced to TokenType.BEARER)");
		}
		if (attributes.containsKey(OAuth2IntrospectionClaimNames.USERNAME)) {
			throw new RuntimeException(
					OAuth2IntrospectionClaimNames.USERNAME
							+ " claim is not configurable (forced to @WithMockAccessToken.name)");
		} else {
			postrPocessedAttributes.put(OAuth2IntrospectionClaimNames.TOKEN_TYPE, TokenType.BEARER);
			putIfNotEmpty(OAuth2IntrospectionClaimNames.USERNAME, username, postrPocessedAttributes);
		}

		final AuthoritiesAndScopes authoritiesAndScopes =
				AuthoritiesAndScopes.get(authorities, scopes, postrPocessedAttributes);

		return new OAuth2IntrospectionAuthenticationToken(
				new OAuth2AccessToken(
						TokenType.BEARER,
						DEFAULT_TOKEN_VALUE,
						(Instant) postrPocessedAttributes.get(OAuth2IntrospectionClaimNames.ISSUED_AT),
						(Instant) postrPocessedAttributes.get(OAuth2IntrospectionClaimNames.EXPIRES_AT),
						authoritiesAndScopes.scopes),
				postrPocessedAttributes,
				authoritiesAndScopes.authorities,
				nullIfEmpty(username));
	}

}
