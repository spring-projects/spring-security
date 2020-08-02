/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.oauth2.core.oidc;

import java.time.Instant;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Tests for {@link OidcUserInfo}
 */
public class OidcIdTokenBuilderTests {

	@Test
	public void buildWhenCalledTwiceThenGeneratesTwoOidcIdTokens() {
		OidcIdToken.Builder idTokenBuilder = OidcIdToken.withTokenValue("token");
		OidcIdToken first = idTokenBuilder.tokenValue("V1").claim("TEST_CLAIM_1", "C1").build();
		OidcIdToken second = idTokenBuilder.tokenValue("V2").claim("TEST_CLAIM_1", "C2").claim("TEST_CLAIM_2", "C3")
				.build();
		assertThat(first.getClaims()).hasSize(1);
		assertThat(first.getClaims().get("TEST_CLAIM_1")).isEqualTo("C1");
		assertThat(first.getTokenValue()).isEqualTo("V1");
		assertThat(second.getClaims()).hasSize(2);
		assertThat(second.getClaims().get("TEST_CLAIM_1")).isEqualTo("C2");
		assertThat(second.getClaims().get("TEST_CLAIM_2")).isEqualTo("C3");
		assertThat(second.getTokenValue()).isEqualTo("V2");
	}

	@Test
	public void expiresAtWhenUsingGenericOrNamedClaimMethodRequiresInstant() {
		OidcIdToken.Builder idTokenBuilder = OidcIdToken.withTokenValue("token");
		Instant now = Instant.now();
		OidcIdToken idToken = idTokenBuilder.expiresAt(now).build();
		assertThat(idToken.getExpiresAt()).isSameAs(now);
		idToken = idTokenBuilder.expiresAt(now).build();
		assertThat(idToken.getExpiresAt()).isSameAs(now);
		assertThatCode(() -> idTokenBuilder.claim(IdTokenClaimNames.EXP, "not an instant").build())
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void issuedAtWhenUsingGenericOrNamedClaimMethodRequiresInstant() {
		OidcIdToken.Builder idTokenBuilder = OidcIdToken.withTokenValue("token");
		Instant now = Instant.now();
		OidcIdToken idToken = idTokenBuilder.issuedAt(now).build();
		assertThat(idToken.getIssuedAt()).isSameAs(now);
		idToken = idTokenBuilder.issuedAt(now).build();
		assertThat(idToken.getIssuedAt()).isSameAs(now);
		assertThatCode(() -> idTokenBuilder.claim(IdTokenClaimNames.IAT, "not an instant").build())
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void subjectWhenUsingGenericOrNamedClaimMethodThenLastOneWins() {
		OidcIdToken.Builder idTokenBuilder = OidcIdToken.withTokenValue("token");
		String generic = new String("sub");
		String named = new String("sub");
		OidcIdToken idToken = idTokenBuilder.subject(named).claim(IdTokenClaimNames.SUB, generic).build();
		assertThat(idToken.getSubject()).isSameAs(generic);
		idToken = idTokenBuilder.claim(IdTokenClaimNames.SUB, generic).subject(named).build();
		assertThat(idToken.getSubject()).isSameAs(named);
	}

	@Test
	public void claimsWhenRemovingAClaimThenIsNotPresent() {
		OidcIdToken.Builder idTokenBuilder = OidcIdToken.withTokenValue("token").claim("needs", "a claim");
		OidcIdToken idToken = idTokenBuilder.subject("sub").claims((claims) -> claims.remove(IdTokenClaimNames.SUB))
				.build();
		assertThat(idToken.getSubject()).isNull();
	}

	@Test
	public void claimsWhenAddingAClaimThenIsPresent() {
		OidcIdToken.Builder idTokenBuilder = OidcIdToken.withTokenValue("token");
		String name = new String("name");
		String value = new String("value");
		OidcIdToken idToken = idTokenBuilder.claims((claims) -> claims.put(name, value)).build();
		assertThat(idToken.getClaims()).hasSize(1);
		assertThat(idToken.getClaims().get(name)).isSameAs(value);
	}

}
