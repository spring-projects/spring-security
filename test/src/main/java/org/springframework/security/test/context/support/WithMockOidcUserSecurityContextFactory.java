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
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.*;

import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.*;

/**
 * Initializes the Spring Security Context with a OAuth2AuthenticationToken instance.
 *
 * @author Nena Raab
 * @see WithMockOidcUser
 */
final class WithMockOidcUserSecurityContextFactory implements
		WithSecurityContextFactory<WithMockOidcUser> {

	public SecurityContext createSecurityContext(WithMockOidcUser withUser) {
		String userId = StringUtils.hasLength(withUser.name()) ? withUser
				.name() : withUser.value();
		if (userId == null) {
			Assert.notNull(userId, "@WithMockOidcUser cannot have null name on both name and value properties");
		}

		Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
		for (String authority : withUser.authorities()) {
			grantedAuthorities.add(new SimpleGrantedAuthority(authority));
		}

		if (grantedAuthorities.isEmpty()) {
			for (String scope : withUser.scopes()) {
				Assert.isTrue(!scope.startsWith("SCOPE_"), "scopes cannot start with SCOPE_ got " + scope);
				grantedAuthorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
			}
		}
		// To align this with the OidcUser that OidcUserService creates, this adds a ROLE_USER
		grantedAuthorities.add(new OidcUserAuthority(getOidcTokenForUser(userId)));

		OidcUser principal = new DefaultOidcUser(grantedAuthorities, getOidcTokenForUser(userId));

		Authentication authentication = new OAuth2AuthenticationToken(
				principal, principal.getAuthorities(), "client-id");

		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authentication);
		return context;
	}

	private static OidcIdToken getOidcTokenForUser(String userId) {
		Map<String, Object> claims = new HashMap<>();
		final Instant issuedAt = Instant.now().minusSeconds(3);
		final Instant expiredAt = Instant.now().plusSeconds(600);

		claims.put(IAT, issuedAt.getEpochSecond());
		claims.put(EXP, expiredAt.getEpochSecond());
		claims.put(SUB, userId);

		return new OidcIdToken("id-token", issuedAt, expiredAt, claims);
	}
}
