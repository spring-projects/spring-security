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

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OidcUserInfo}
 */
public class OidcUserInfoBuilderTests {

	@Test
	public void buildWhenCalledTwiceThenGeneratesTwoOidcUserInfos() {
		OidcUserInfo.Builder userInfoBuilder = OidcUserInfo.builder();

		OidcUserInfo first = userInfoBuilder.claim("TEST_CLAIM_1", "C1").build();

		OidcUserInfo second = userInfoBuilder.claim("TEST_CLAIM_1", "C2").claim("TEST_CLAIM_2", "C3").build();

		assertThat(first.getClaims()).hasSize(1);
		assertThat(first.getClaims().get("TEST_CLAIM_1")).isEqualTo("C1");

		assertThat(second.getClaims()).hasSize(2);
		assertThat(second.getClaims().get("TEST_CLAIM_1")).isEqualTo("C2");
		assertThat(second.getClaims().get("TEST_CLAIM_2")).isEqualTo("C3");
	}

	@Test
	public void subjectWhenUsingGenericOrNamedClaimMethodThenLastOneWins() {
		OidcUserInfo.Builder userInfoBuilder = OidcUserInfo.builder();

		String generic = new String("sub");
		String named = new String("sub");

		OidcUserInfo userInfo = userInfoBuilder.subject(named).claim(IdTokenClaimNames.SUB, generic).build();
		assertThat(userInfo.getSubject()).isSameAs(generic);

		userInfo = userInfoBuilder.claim(IdTokenClaimNames.SUB, generic).subject(named).build();
		assertThat(userInfo.getSubject()).isSameAs(named);
	}

	@Test
	public void claimsWhenRemovingAClaimThenIsNotPresent() {
		OidcUserInfo.Builder userInfoBuilder = OidcUserInfo.builder().claim("needs", "a claim");

		OidcUserInfo userInfo = userInfoBuilder.subject("sub").claims((claims) -> claims.remove(IdTokenClaimNames.SUB))
				.build();
		assertThat(userInfo.getSubject()).isNull();
	}

	@Test
	public void claimsWhenAddingAClaimThenIsPresent() {
		OidcUserInfo.Builder userInfoBuilder = OidcUserInfo.builder();

		String name = new String("name");
		String value = new String("value");
		OidcUserInfo userInfo = userInfoBuilder.claims((claims) -> claims.put(name, value)).build();

		assertThat(userInfo.getClaims()).hasSize(1);
		assertThat(userInfo.getClaims().get(name)).isSameAs(value);
	}

}
