/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.test.context.support;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.*;

/**
 * A {@link WithMockOidcUserSecurityContextFactory} that works with {@link WithMockOidcUser}.
 * <p>
 * Initializes the Spring Security Context with a OAuth2AuthenticationToken instance, which comes with
 * an encoded oidc token with some default claims but without header and signature.
 *
 * @author Nena Raab
 * @see WithMockOidcUser
 * @since 5.3
 */
final class WithMockOidcUserSecurityContextFactory implements
		WithSecurityContextFactory<WithMockOidcUser> {

	public SecurityContext createSecurityContext(WithMockOidcUser withUser) {
		String userId = StringUtils.hasLength(withUser.name()) ? withUser
				.name() : withUser.value();
		if (userId == null) {
			throw new IllegalArgumentException(withUser
					+ " cannot have null user name/id on both name and value properties");
		}

		List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
		for (String authority : withUser.authorities()) {
			grantedAuthorities.add(new SimpleGrantedAuthority(authority));
		}

		OidcUser principal = new DefaultOidcUser(grantedAuthorities,
				new OidcIdTokenFactory(userId, withUser.clientId(), withUser.nameTokenClaim()).build(),
				withUser.nameTokenClaim());

		Authentication authentication = new OAuth2AuthenticationToken(
				principal, principal.getAuthorities(), withUser.clientId());

		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authentication);
		return context;
	}

	private class OidcIdTokenFactory {
		private Map<String, Object> claims = new HashMap<>();
		final Instant expiredAt = new GregorianCalendar().toInstant().plusSeconds(600);
		final Instant issuedAt = new GregorianCalendar().toInstant().minusSeconds(3);

		OidcIdTokenFactory(String userId, String clientId, String userIdClaimName) {
			claims.put("client_id", clientId); // mandatory
			claims.put("iat", issuedAt.getEpochSecond());
			claims.put("exp", expiredAt.getEpochSecond());
			claims.put(userIdClaimName, userId);
		}

		public OidcIdToken build() {
			return new OidcIdToken(emptyTokenBase64Encode(), issuedAt, expiredAt, claims);
		}

		private String emptyTokenBase64Encode() {
			byte[] emptyToken = "{}".getBytes();
			return Base64.getUrlEncoder().withoutPadding().encodeToString(emptyToken);
		}
	}
}
