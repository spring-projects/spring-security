/*
 * Copyright 2002-2017 the original author or authors.
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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

/**
 * Tests for {@link Jwt.Builder}.
 */
public class JwtBuilderTests {

	@Test()
	public void builderCanBeReused() {
		final Jwt.Builder<?> tokensBuilder = Jwt.builder();
		
		final Jwt first = tokensBuilder
				.tokenValue("V1")
				.header("TEST_HEADER_1", "H1")
				.claim("TEST_CLAIM_1", "C1")
				.build();
		
		final Jwt second = tokensBuilder
				.tokenValue("V2")
				.header("TEST_HEADER_1", "H2")
				.header("TEST_HEADER_2", "H3")
				.claim("TEST_CLAIM_1", "C2")
				.claim("TEST_CLAIM_2", "C3")
				.build();

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
}
