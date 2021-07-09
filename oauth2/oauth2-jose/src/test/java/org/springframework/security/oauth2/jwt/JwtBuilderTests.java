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

package org.springframework.security.oauth2.jwt;

import java.time.Instant;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link Jwt.Builder}.
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @author Josh Cummings
 */
public class JwtBuilderTests {

	@Test
	public void buildWhenCalledTwiceThenGeneratesTwoJwts() {
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token");
		// @formatter:off
		Jwt first = jwtBuilder.tokenValue("V1")
				.header("TEST_HEADER_1", "H1")
				.claim("TEST_CLAIM_1", "C1")
				.build();
		Jwt second = jwtBuilder.tokenValue("V2")
				.header("TEST_HEADER_1", "H2")
				.header("TEST_HEADER_2", "H3")
				.claim("TEST_CLAIM_1", "C2")
				.claim("TEST_CLAIM_2", "C3")
				.build();
		// @formatter:on
		assertThat(first.getHeaders()).hasSize(1);
		assertThat(first.getHeaders().get("TEST_HEADER_1")).isEqualTo("H1");
		assertThat(first.getClaims()).hasSize(1);
		assertThat(first.getClaims().get("TEST_CLAIM_1")).isEqualTo("C1");
		assertThat(first.getTokenValue()).isEqualTo("V1");
		assertThat(second.getHeaders()).hasSize(2);
		assertThat(second.getHeaders().get("TEST_HEADER_1")).isEqualTo("H2");
		assertThat(second.getHeaders().get("TEST_HEADER_2")).isEqualTo("H3");
		assertThat(second.getClaims()).hasSize(2);
		assertThat(second.getClaims().get("TEST_CLAIM_1")).isEqualTo("C2");
		assertThat(second.getClaims().get("TEST_CLAIM_2")).isEqualTo("C3");
		assertThat(second.getTokenValue()).isEqualTo("V2");
	}

	@Test
	public void expiresAtWhenUsingGenericOrNamedClaimMethodRequiresInstant() {
		// @formatter:off
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token")
				.header("needs", "a header");
		// @formatter:on
		Instant now = Instant.now();
		Jwt jwt = jwtBuilder.expiresAt(now).build();
		assertThat(jwt.getExpiresAt()).isSameAs(now);
		jwt = jwtBuilder.expiresAt(now).build();
		assertThat(jwt.getExpiresAt()).isSameAs(now);
		assertThatIllegalArgumentException()
				.isThrownBy(() -> jwtBuilder.claim(JwtClaimNames.EXP, "not an instant").build());
	}

	@Test
	public void issuedAtWhenUsingGenericOrNamedClaimMethodRequiresInstant() {
		// @formatter:off
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token")
				.header("needs", "a header");
		// @formatter:on
		Instant now = Instant.now();
		Jwt jwt = jwtBuilder.issuedAt(now).build();
		assertThat(jwt.getIssuedAt()).isSameAs(now);
		jwt = jwtBuilder.issuedAt(now).build();
		assertThat(jwt.getIssuedAt()).isSameAs(now);
		assertThatIllegalArgumentException()
				.isThrownBy(() -> jwtBuilder.claim(JwtClaimNames.IAT, "not an instant").build());
	}

	@Test
	public void subjectWhenUsingGenericOrNamedClaimMethodThenLastOneWins() {
		// @formatter:off
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token")
				.header("needs", "a header");
		// @formatter:on
		String generic = new String("sub");
		String named = new String("sub");
		Jwt jwt = jwtBuilder.subject(named).claim(JwtClaimNames.SUB, generic).build();
		assertThat(jwt.getSubject()).isSameAs(generic);
		jwt = jwtBuilder.claim(JwtClaimNames.SUB, generic).subject(named).build();
		assertThat(jwt.getSubject()).isSameAs(named);
	}

	@Test
	public void claimsWhenRemovingAClaimThenIsNotPresent() {
		// @formatter:off
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token")
				.claim("needs", "a claim")
				.header("needs", "a header");
		Jwt jwt = jwtBuilder.subject("sub")
				.claims((claims) -> claims.remove(JwtClaimNames.SUB))
				.build();
		// @formatter:on
		assertThat(jwt.getSubject()).isNull();
	}

	@Test
	public void claimsWhenAddingAClaimThenIsPresent() {
		// @formatter:off
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token")
				.header("needs", "a header");
		// @formatter:on
		String name = new String("name");
		String value = new String("value");
		Jwt jwt = jwtBuilder.claims((claims) -> claims.put(name, value)).build();
		assertThat(jwt.getClaims()).hasSize(1);
		assertThat(jwt.getClaims().get(name)).isSameAs(value);
	}

	@Test
	public void headersWhenRemovingAClaimThenIsNotPresent() {
		// @formatter:off
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token")
				.claim("needs", "a claim")
				.header("needs", "a header");
		Jwt jwt = jwtBuilder.header("alg", "none")
				.headers((headers) -> headers.remove("alg"))
				.build();
		// @formatter:on
		assertThat(jwt.getHeaders().get("alg")).isNull();
	}

	@Test
	public void headersWhenAddingAClaimThenIsPresent() {
		// @formatter:off
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token")
				.claim("needs", "a claim");
		// @formatter:on
		String name = new String("name");
		String value = new String("value");
		// @formatter:off
		Jwt jwt = jwtBuilder.headers((headers) -> headers.put(name, value))
				.build();
		// @formatter:on
		assertThat(jwt.getHeaders()).hasSize(1);
		assertThat(jwt.getHeaders().get(name)).isSameAs(value);
	}

}
