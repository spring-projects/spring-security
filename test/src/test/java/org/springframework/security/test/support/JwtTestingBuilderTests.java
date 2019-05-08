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
package org.springframework.security.test.support;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.test.support.JwtAuthenticationTokenTestingBuilder.JwtTestingBuilder;

/**
 * 
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class JwtTestingBuilderTests {

	@Test
	public void testDefaultValuesAreSet() {
		final Jwt actual = new JwtTestingBuilder().build();

		assertThat(actual.getTokenValue()).isEqualTo("test.jwt.value");
		assertThat(actual.getClaimAsString(JwtClaimNames.SUB)).isEqualTo("user");
		assertThat(actual.getHeaders()).hasSize(1);
	}

	@Test
	public void iatClaimAndExpClaimSetIssuedAtAndExpiresAt() {
		final Jwt actual = new JwtTestingBuilder()
					.claim(JwtClaimNames.IAT, Instant.parse("2019-03-21T13:52:25Z"))
					.claim(JwtClaimNames.EXP, Instant.parse("2019-03-22T13:52:25Z"))
				.build();

		assertThat(actual.getIssuedAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getExpiresAt()).isEqualTo(Instant.parse("2019-03-22T13:52:25Z"));
		assertThat(actual.getClaimAsInstant(JwtClaimNames.IAT)).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getClaimAsInstant(JwtClaimNames.EXP)).isEqualTo(Instant.parse("2019-03-22T13:52:25Z"));
	}

}
