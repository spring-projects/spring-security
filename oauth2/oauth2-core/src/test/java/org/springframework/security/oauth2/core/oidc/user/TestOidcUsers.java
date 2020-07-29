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

package org.springframework.security.oauth2.core.oidc.user;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

/**
 * @author Joe Grandja
 */
public final class TestOidcUsers {

	private TestOidcUsers() {
	}

	public static DefaultOidcUser create() {
		OidcIdToken idToken = idToken();
		OidcUserInfo userInfo = userInfo();
		return new DefaultOidcUser(authorities(idToken, userInfo), idToken, userInfo);
	}

	private static OidcIdToken idToken() {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plusSeconds(3600);
		return OidcIdToken.withTokenValue("id-token").issuedAt(issuedAt).expiresAt(expiresAt).subject("subject")
				.issuer("http://localhost/issuer")
				.audience(Collections.unmodifiableSet(new LinkedHashSet<>(Collections.singletonList("client"))))
				.authorizedParty("client").build();
	}

	private static OidcUserInfo userInfo() {
		return OidcUserInfo.builder().subject("subject").name("full name").build();
	}

	private static Collection<? extends GrantedAuthority> authorities(OidcIdToken idToken, OidcUserInfo userInfo) {
		return new LinkedHashSet<>(Arrays.asList(new OidcUserAuthority(idToken, userInfo),
				new SimpleGrantedAuthority("SCOPE_read"), new SimpleGrantedAuthority("SCOPE_write")));
	}

}
