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

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.EXP;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.IAT;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.SUB;

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

		Jwt first = jwtBuilder.tokenValue("V1").header("TEST_HEADER_1", "H1").claim("TEST_CLAIM_1", "C1").build();

		Jwt second = jwtBuilder.tokenValue("V2").header("TEST_HEADER_1", "H2").header("TEST_HEADER_2", "H3")
				.claim("TEST_CLAIM_1", "C2").claim("TEST_CLAIM_2", "C3").build();

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
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token").header("needs", "a header");

		Instant now = Instant.now();

		Jwt jwt = jwtBuilder.expiresAt(now).build();
		assertThat(jwt.getExpiresAt()).isSameAs(now);

		jwt = jwtBuilder.expiresAt(now).build();
		assertThat(jwt.getExpiresAt()).isSameAs(now);

		assertThatCode(() -> jwtBuilder.claim(EXP, "not an instant").build())
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void issuedAtWhenUsingGenericOrNamedClaimMethodRequiresInstant() {
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token").header("needs", "a header");

		Instant now = Instant.now();

		Jwt jwt = jwtBuilder.issuedAt(now).build();
		assertThat(jwt.getIssuedAt()).isSameAs(now);

		jwt = jwtBuilder.issuedAt(now).build();
		assertThat(jwt.getIssuedAt()).isSameAs(now);

		assertThatCode(() -> jwtBuilder.claim(IAT, "not an instant").build())
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void subjectWhenUsingGenericOrNamedClaimMethodThenLastOneWins() {
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token").header("needs", "a header");

		String generic = new String("sub");
		String named = new String("sub");

		Jwt jwt = jwtBuilder.subject(named).claim(SUB, generic).build();
		assertThat(jwt.getSubject()).isSameAs(generic);

		jwt = jwtBuilder.claim(SUB, generic).subject(named).build();
		assertThat(jwt.getSubject()).isSameAs(named);
	}

	@Test
	public void claimsWhenRemovingAClaimThenIsNotPresent() {
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token").claim("needs", "a claim").header("needs", "a header");

		Jwt jwt = jwtBuilder.subject("sub").claims(claims -> claims.remove(SUB)).build();
		assertThat(jwt.getSubject()).isNull();
	}

	@Test
	public void claimsWhenAddingAClaimThenIsPresent() {
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token").header("needs", "a header");

		String name = new String("name");
		String value = new String("value");
		Jwt jwt = jwtBuilder.claims(claims -> claims.put(name, value)).build();

		assertThat(jwt.getClaims()).hasSize(1);
		assertThat(jwt.getClaims().get(name)).isSameAs(value);
	}

	@Test
	public void headersWhenRemovingAClaimThenIsNotPresent() {
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token").claim("needs", "a claim").header("needs", "a header");

		Jwt jwt = jwtBuilder.header("alg", "none").headers(headers -> headers.remove("alg")).build();
		assertThat(jwt.getHeaders().get("alg")).isNull();
	}

	@Test
	public void headersWhenAddingAClaimThenIsPresent() {
		Jwt.Builder jwtBuilder = Jwt.withTokenValue("token").claim("needs", "a claim");

		String name = new String("name");
		String value = new String("value");
		Jwt jwt = jwtBuilder.headers(headers -> headers.put(name, value)).build();

		assertThat(jwt.getHeaders()).hasSize(1);
		assertThat(jwt.getHeaders().get(name)).isSameAs(value);
	}

}
