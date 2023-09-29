/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.authentication.logout;

import java.time.Instant;
import java.util.Collections;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;

public final class TestOidcLogoutTokens {

	public static OidcLogoutToken.Builder withUser(OidcUser user) {
		OidcLogoutToken.Builder builder = OidcLogoutToken.withTokenValue("token")
			.audience(Collections.singleton("client-id"))
			.issuedAt(Instant.now())
			.issuer(user.getIssuer().toString())
			.jti("id")
			.subject(user.getSubject());
		if (user.hasClaim(LogoutTokenClaimNames.SID)) {
			builder.sessionId(user.getClaimAsString(LogoutTokenClaimNames.SID));
		}
		return builder;
	}

	public static OidcLogoutToken.Builder withSessionId(String issuer, String sessionId) {
		return OidcLogoutToken.withTokenValue("token")
			.audience(Collections.singleton("client-id"))
			.issuedAt(Instant.now())
			.issuer(issuer)
			.jti("id")
			.sessionId(sessionId);
	}

	public static OidcLogoutToken.Builder withSubject(String issuer, String subject) {
		return OidcLogoutToken.withTokenValue("token")
			.audience(Collections.singleton("client-id"))
			.issuedAt(Instant.now())
			.issuer(issuer)
			.jti("id")
			.subject(subject);
	}

	private TestOidcLogoutTokens() {

	}

}
